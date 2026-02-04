#include "proxy_tcp.h"
#include "worker.h"
#include "nat_table.h"
#include "tls_parser.h"
#include "app_config.h"
#include "traffic_manager.h"
#include "lwip_handler.h"
#include "main_dispatcher.h"
#include "geo_checker.h"
#include "rule_manager.h"
#include <atomic>
#include <mutex>
#include <vector>
#include <deque>
#include <string>
#include <algorithm>

const size_t MAX_TX_QUEUE_SIZE = 4 * 1024 * 1024;    // 4MB High Water Mark
const size_t RESUME_TX_QUEUE_SIZE = 2 * 1024 * 1024; // 2MB Low Water Mark

// --- TCP Logic with Worker Pool ---
struct TcpCtx {
    struct tcp_pcb* client_pcb;
    SOCKET proxy_socket;
    std::atomic<bool> closed;
    std::atomic<bool> connected;
    bool read_paused;
    NatEntry target;
    
    // Client Info for Logging
    uint32_t client_ip;
    uint16_t client_port;

    bool is_direct; // Add this for bypass
    
    // Sniffing
    std::vector<uint8_t> sni_buffer;
    std::vector<uint8_t> upstream_data; 
    std::string detected_domain;        
    
    // Zero-Copy Queue
    std::deque<std::vector<uint8_t>> tx_queue;
    size_t tx_acked_offset;   
    size_t tx_written_idx;    
    size_t tx_written_offset; 
    
    std::mutex data_mtx;
    Worker* worker;

    enum State { PRE_CONNECT, CONNECTING, HANDSHAKE, ESTABLISHED } state;

    TcpCtx() : client_pcb(NULL), proxy_socket(INVALID_SOCKET), closed(false), connected(false), read_paused(false), worker(NULL), state(PRE_CONNECT),
               tx_acked_offset(0), tx_written_idx(0), tx_written_offset(0), client_ip(0), client_port(0), is_direct(false) {
        sni_buffer.reserve(g_config.max_sni_len);
        upstream_data.reserve(8192); 
    }
};


void close_tcp_ctx(TcpCtx* ctx);
void handle_proxy_read(TcpCtx* ctx);
void connect_to_proxy_async(TcpCtx* ctx);

void final_cleanup_on_main(TcpCtx* ctx) {
    std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
    if (ctx->client_pcb) {
        tcp_arg(ctx->client_pcb, NULL);
        tcp_recv(ctx->client_pcb, NULL);
        tcp_sent(ctx->client_pcb, NULL);
        tcp_err(ctx->client_pcb, NULL);
        tcp_close(ctx->client_pcb);
        ctx->client_pcb = NULL;
    }
    delete ctx;
}

void internal_close_on_worker(TcpCtx* ctx) {
    if (ctx->proxy_socket != INVALID_SOCKET) {
        ctx->worker->remove_socket(ctx->proxy_socket, [ctx]() {
            closesocket(ctx->proxy_socket);
            MainDispatcher::instance().queue_task([ctx]() {
                final_cleanup_on_main(ctx);
            });
        });
    } else {
        MainDispatcher::instance().queue_task([ctx]() {
            final_cleanup_on_main(ctx);
        });
    }
}

void close_tcp_ctx(TcpCtx* ctx) {
    if (!ctx || ctx->closed.exchange(true)) return;

    if (ctx->worker) {
        ctx->worker->queue_task([ctx]() {
            internal_close_on_worker(ctx);
        });
    } else {
        MainDispatcher::instance().queue_task([ctx]() {
            final_cleanup_on_main(ctx);
        });
    }
}

void try_send_downstream(TcpCtx* ctx) {
    if (!ctx || ctx->closed || !ctx->client_pcb) return;

    while (ctx->tx_written_idx < ctx->tx_queue.size()) {
        auto& buf = ctx->tx_queue[ctx->tx_written_idx];
        
        if (ctx->tx_written_offset >= buf.size()) {
            ctx->tx_written_idx++;
            ctx->tx_written_offset = 0;
            continue;
        }

        u16_t limit = tcp_sndbuf(ctx->client_pcb);
        if (limit == 0) break; 

        size_t remaining = buf.size() - ctx->tx_written_offset;
        u16_t chunk = (u16_t)((std::min)((size_t)limit, remaining));
        if (chunk == 0) break;

        err_t err = tcp_write(ctx->client_pcb, 
                              buf.data() + ctx->tx_written_offset, 
                              chunk, 
                              0); 
                              
        if (err == ERR_OK) {
            ctx->tx_written_offset += chunk;
            if (ctx->tx_written_offset >= buf.size()) {
                ctx->tx_written_idx++;
                ctx->tx_written_offset = 0;
            }
            tcp_output(ctx->client_pcb);
        } else if (err == ERR_MEM) {
            break;
        } else {
            close_tcp_ctx(ctx);
            return;
        }
    }
}

err_t tcp_client_sent(void* arg, struct tcp_pcb* tpcb, u16_t len) {
    TcpCtx* ctx = (TcpCtx*)arg;
    if (!ctx || ctx->closed) return ERR_OK;

    while (len > 0 && !ctx->tx_queue.empty()) {
        auto& head = ctx->tx_queue.front();
        size_t unacked = head.size() - ctx->tx_acked_offset;
        
        if (len >= unacked) {
            len -= (u16_t)unacked;
            ctx->tx_queue.pop_front();
            ctx->tx_acked_offset = 0;
            if (ctx->tx_written_idx > 0) ctx->tx_written_idx--;
        } else {
            ctx->tx_acked_offset += len;
            len = 0;
        }
    }

    try_send_downstream(ctx);
    return ERR_OK;
}

void handle_proxy_read(TcpCtx* ctx) {
    if (ctx->closed) return;
    
    thread_local std::vector<uint8_t> read_buf(262144);
    
    int r = recv(ctx->proxy_socket, (char*)read_buf.data(), (int)read_buf.size(), 0);
    
    if (r > 0) {
        TrafficManager::instance().report_proxy_rx(r, ctx->is_direct);
        LOG_DEBUG("[TCP] Recv %d bytes: %d.%d.%d.%d:%d <- %d.%d.%d.%d:%d\n", r,
            ctx->client_ip & 0xFF, (ctx->client_ip >> 8) & 0xFF, (ctx->client_ip >> 16) & 0xFF, (ctx->client_ip >> 24) & 0xFF, ntohs(ctx->client_port),
            ctx->target.original_dst_ip & 0xFF, (ctx->target.original_dst_ip >> 8) & 0xFF, (ctx->target.original_dst_ip >> 16) & 0xFF, (ctx->target.original_dst_ip >> 24) & 0xFF, ntohs(ctx->target.original_dst_port));
        std::vector<uint8_t> data(read_buf.begin(), read_buf.begin() + r);
        
        MainDispatcher::instance().queue_task([ctx, d = std::move(data)]() mutable {
            std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
            if (ctx->client_pcb && !ctx->closed) {
                ctx->tx_queue.push_back(std::move(d));
                try_send_downstream(ctx);
            }
        });
    } else if (r == 0) {
        close_tcp_ctx(ctx);
    } else {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            close_tcp_ctx(ctx);
        }
    }
}

void handle_handshake_read(TcpCtx* ctx) {
    if (ctx->closed) return;
    char buf[4096];
    int r = recv(ctx->proxy_socket, buf, sizeof(buf), 0);
    
    if (r > 0) {
        TrafficManager::instance().report_proxy_rx(r, false); // Handshake is always proxy
        std::string s(buf, r);
        size_t header_end = s.find("\r\n\r\n");
        
        if (header_end != std::string::npos) {
            std::string header = s.substr(0, header_end);
            if (header.find("200") != std::string::npos) {
                LOG_INFO("[TCP] Proxy Tunnel Established: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
                    ctx->client_ip & 0xFF, (ctx->client_ip >> 8) & 0xFF, (ctx->client_ip >> 16) & 0xFF, (ctx->client_ip >> 24) & 0xFF, ntohs(ctx->client_port),
                    ctx->target.original_dst_ip & 0xFF, (ctx->target.original_dst_ip >> 8) & 0xFF, (ctx->target.original_dst_ip >> 16) & 0xFF, (ctx->target.original_dst_ip >> 24) & 0xFF, ntohs(ctx->target.original_dst_port));
                
                {
                    std::lock_guard<std::mutex> lock(ctx->data_mtx);
                    if (!ctx->upstream_data.empty()) {
                         const char* ptr = (const char*)ctx->upstream_data.data();
                         int remaining = (int)ctx->upstream_data.size();
                         
                         // Try to send all data at once. On a fresh connection, this should not block.
                         // If it blocks (WSAEWOULDBLOCK), it's better to close than to Sleep(1) and block the Worker.
                         while (remaining > 0) {
                             int sent = send(ctx->proxy_socket, ptr, remaining, 0);
                             if (sent == SOCKET_ERROR) {
                                 // WSAEWOULDBLOCK on a fresh handshake implies severe congestion.
                                 // We fail fast to protect other connections on this Worker.
                                 int err = WSAGetLastError();
                                 if (err != WSAEWOULDBLOCK) {
                                     LOG_INFO("[TCP] Handshake flush failed: %d\n", err);
                                 }
                                 close_tcp_ctx(ctx);
                                 return;
                             }
                             TrafficManager::instance().report_proxy_tx(sent, false); // Handshake is always proxy
                             ptr += sent;
                             remaining -= sent;
                         }
                         ctx->upstream_data.clear();
                    }
                    ctx->connected = true;
                    ctx->state = TcpCtx::ESTABLISHED;
                }

                size_t payload_start = header_end + 4;
                if (payload_start < (size_t)r) {
                    std::vector<uint8_t> extra_data((uint8_t*)(buf + payload_start), (uint8_t*)(buf + r));
                    
                    MainDispatcher::instance().queue_task([ctx, d = std::move(extra_data)]() mutable {
                        std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
                        if (ctx->client_pcb && !ctx->closed) {
                            ctx->tx_queue.push_back(std::move(d));
                            try_send_downstream(ctx);
                        }
                    });
                }
                
                ctx->worker->add_socket(
                    ctx->proxy_socket,
                    [ctx](char*, int, sockaddr_in*) { handle_proxy_read(ctx); },
                    nullptr,
                    [ctx]() { close_tcp_ctx(ctx); }
                );
            } else {
                LOG_INFO("[TCP] Handshake Rejected: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
                    ctx->client_ip & 0xFF, (ctx->client_ip >> 8) & 0xFF, (ctx->client_ip >> 16) & 0xFF, (ctx->client_ip >> 24) & 0xFF, ntohs(ctx->client_port),
                    ctx->target.original_dst_ip & 0xFF, (ctx->target.original_dst_ip >> 8) & 0xFF, (ctx->target.original_dst_ip >> 16) & 0xFF, (ctx->target.original_dst_ip >> 24) & 0xFF, ntohs(ctx->target.original_dst_port));
                close_tcp_ctx(ctx);
            }
        } else { 
            close_tcp_ctx(ctx);
        }
    } else if (r == 0) {
        close_tcp_ctx(ctx);
    } else {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            close_tcp_ctx(ctx);
        }
    }
}

void handle_proxy_connect(TcpCtx* ctx) {
    if (ctx->closed) return;

    int err = 0; int len = sizeof(err);
    getsockopt(ctx->proxy_socket, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
    if (err != 0) {
        close_tcp_ctx(ctx);
        return;
    }

    if (ctx->is_direct) {
        LOG_INFO("[TCP] Direct Tunnel Established: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
            ctx->client_ip & 0xFF, (ctx->client_ip >> 8) & 0xFF, (ctx->client_ip >> 16) & 0xFF, (ctx->client_ip >> 24) & 0xFF, ntohs(ctx->client_port),
            ctx->target.original_dst_ip & 0xFF, (ctx->target.original_dst_ip >> 8) & 0xFF, (ctx->target.original_dst_ip >> 16) & 0xFF, (ctx->target.original_dst_ip >> 24) & 0xFF, ntohs(ctx->target.original_dst_port));
        
        {
            std::lock_guard<std::mutex> lock(ctx->data_mtx);
            if (!ctx->upstream_data.empty()) {
                 int sent = send(ctx->proxy_socket, (const char*)ctx->upstream_data.data(), (int)ctx->upstream_data.size(), 0);
                 if (sent > 0) TrafficManager::instance().report_proxy_tx(sent, true); // Direct
                 ctx->upstream_data.clear();
            }
            ctx->connected = true;
            ctx->state = TcpCtx::ESTABLISHED;
        }

        ctx->worker->add_socket(
            ctx->proxy_socket,
            [ctx](char*, int, sockaddr_in*) { handle_proxy_read(ctx); },
            nullptr,
            [ctx]() { close_tcp_ctx(ctx); }
        );
        return;
    }

    uint32_t ip = ctx->target.original_dst_ip;

    std::string sni = ctx->detected_domain;
    std::string ip_str = std::to_string(ip & 0xFF) + "." +
        std::to_string((ip >> 8) & 0xFF) + "." +
        std::to_string((ip >> 16) & 0xFF) + "." +
        std::to_string((ip >> 24) & 0xFF);

    std::string host = !sni.empty() ? sni : ip_str;
    std::string host_print = !sni.empty() ? "SNI/HOST: " + sni : "IP: " + ip_str;
    char cmd[1024];
    uint16_t port = ntohs(ctx->target.original_dst_port);

    LOG_INFO("[TCP] %s (%d.%d.%d.%d:%d)\n", host_print.c_str(),
        ctx->client_ip & 0xFF, (ctx->client_ip >> 8) & 0xFF, (ctx->client_ip >> 16) & 0xFF, (ctx->client_ip >> 24) & 0xFF, ntohs(ctx->client_port));
    sprintf_s(cmd, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host.c_str(), port, host.c_str(), port);
    
    int sent = send(ctx->proxy_socket, cmd, (int)strlen(cmd), 0);
    if (sent == SOCKET_ERROR) {
         if (WSAGetLastError() != WSAEWOULDBLOCK) {
             close_tcp_ctx(ctx);
             return;
         }
         close_tcp_ctx(ctx); 
         return;
    }
    TrafficManager::instance().report_proxy_tx(sent, false); // Proxy (CONNECT cmd)

    ctx->state = TcpCtx::HANDSHAKE;

    ctx->worker->add_socket(
        ctx->proxy_socket,
        [ctx](char*, int, sockaddr_in*) { handle_handshake_read(ctx); }, 
        nullptr, 
        [ctx]() { close_tcp_ctx(ctx); }
    );
}

void connect_to_proxy_async(TcpCtx* ctx) {
    if (!ctx->worker) {
        ctx->worker = WorkerPool::instance().get_worker(ctx->target.original_dst_port);
        if (!ctx->worker) ctx->worker = WorkerPool::instance().get_next_worker();
    }
    ctx->state = TcpCtx::CONNECTING;
    ctx->worker->queue_task([ctx]() {
        if (ctx->closed) return;
        ctx->proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (ctx->proxy_socket == INVALID_SOCKET) { close_tcp_ctx(ctx); return; }
        u_long mode = 1; ioctlsocket(ctx->proxy_socket, FIONBIO, &mode);

        struct WinSockAddr {
            short sin_family;
            unsigned short sin_port;
            struct { unsigned long S_addr; } sin_addr;
            char sin_zero[8];
        } addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        
        unsigned int a, b, c, d;
        if (ctx->is_direct) {
            addr.sin_addr.S_addr = ctx->target.original_dst_ip;
            addr.sin_port = ctx->target.original_dst_port;
        } else {
            if (sscanf_s(g_config.proxy_ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                addr.sin_addr.S_addr = (a) | (b << 8) | (c << 16) | (d << 24);
            } else { addr.sin_addr.S_addr = 0x0100007F; }
            addr.sin_port = htons(g_config.proxy_port);
        }

        ctx->worker->connect_async(
            ctx->proxy_socket, *(sockaddr_in*)&addr, 
            [ctx]() { handle_proxy_connect(ctx); }
        );
    });
}

err_t tcp_client_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    TcpCtx* ctx = (TcpCtx*)arg;
    if (!ctx || ctx->closed) {
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    if (!p) { close_tcp_ctx(ctx); return ERR_OK; }
    tcp_recved(tpcb, p->tot_len);

    if (p->tot_len > 0) {
        LOG_DEBUG("[TCP] Forward %d bytes: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", p->tot_len,
            ctx->client_ip & 0xFF, (ctx->client_ip >> 8) & 0xFF, (ctx->client_ip >> 16) & 0xFF, (ctx->client_ip >> 24) & 0xFF, ntohs(ctx->client_port),
            ctx->target.original_dst_ip & 0xFF, (ctx->target.original_dst_ip >> 8) & 0xFF, (ctx->target.original_dst_ip >> 16) & 0xFF, (ctx->target.original_dst_ip >> 24) & 0xFF, ntohs(ctx->target.original_dst_port));
    }

    if (ctx->connected && ctx->worker) {
        std::vector<uint8_t> data;
        data.reserve(p->tot_len);
        for (struct pbuf* q = p; q != NULL; q = q->next) {
            data.insert(data.end(), (uint8_t*)q->payload, (uint8_t*)q->payload + q->len);
        }
        ctx->worker->queue_task([ctx, d = std::move(data)]() {
            if (ctx->closed) return;
            if (ctx->proxy_socket != INVALID_SOCKET) {
                int sent = send(ctx->proxy_socket, (const char*)d.data(), (int)d.size(), 0);
                if (sent > 0) TrafficManager::instance().report_proxy_tx(sent, ctx->is_direct);
            }
        });
    } else {
        std::lock_guard<std::mutex> lock(ctx->data_mtx);
        for (struct pbuf* q = p; q != NULL; q = q->next) {
            uint8_t* d = (uint8_t*)q->payload;
            ctx->upstream_data.insert(ctx->upstream_data.end(), d, d + q->len);
            
            if (ctx->state == TcpCtx::PRE_CONNECT) {
                if (ctx->sni_buffer.size() < g_config.max_sni_len) {
                    size_t to_copy = (std::min)((size_t)q->len, (size_t)(g_config.max_sni_len - ctx->sni_buffer.size()));
                    ctx->sni_buffer.insert(ctx->sni_buffer.end(), d, d + to_copy);
                }
            }
        }
        
        if (ctx->state == TcpCtx::PRE_CONNECT) {
            bool ready = false;
            // 1. TLS Check
            if (ctx->sni_buffer.size() >= 5 && ctx->sni_buffer[0] == 0x16) {
                uint16_t tls_len = ((uint16_t)ctx->sni_buffer[3] << 8) | ctx->sni_buffer[4];
                if (ctx->sni_buffer.size() >= (size_t)5 + tls_len) {
                    ready = true; 
                }
            }
            // 2. HTTP Check
            else if (is_http_start(ctx->sni_buffer.data(), ctx->sni_buffer.size())) {
                std::string host = parse_http_host(ctx->sni_buffer.data(), ctx->sni_buffer.size());
                if (!host.empty()) {
                    ready = true; 
                } else if (ctx->sni_buffer.size() > 1024) {
                    ready = true; 
                }
            }
            // 3. Unknown Check
            else if (ctx->sni_buffer.size() > 64) {
                ready = true;
            }
            
            if (ready) {
                std::string sni = parse_tls_sni(ctx->sni_buffer.data(), ctx->sni_buffer.size());
                if (sni.empty()) {
                    sni = parse_http_host(ctx->sni_buffer.data(), ctx->sni_buffer.size());
                }
                
                if (!sni.empty()) {
                    ctx->detected_domain = sni;
                    
                    // 0. Custom Rules (Highest Priority)
                    RouteAction action = RuleManager::instance().match_domain(sni);
                    if (action == RouteAction::DIRECT) {
                        ctx->is_direct = true;
                        LOG_INFO("[TCP] Domain Rule: %s -> Direct.\n", sni.c_str());
                    } else if (action == RouteAction::PROXY) {
                        ctx->is_direct = false;
                        LOG_INFO("[TCP] Domain Rule: %s -> Proxy.\n", sni.c_str());
                    } else if (action == RouteAction::BLOCK) {
                        LOG_INFO("[TCP] Domain Rule: %s -> Block.\n", sni.c_str());
                        close_tcp_ctx(ctx);
                        return ERR_ABRT;
                    } else {
                        // 1. GeoIP/GeoSite Checks (Fallback)
                        if (GeoChecker::instance().is_cn_domain(sni) || 
                            GeoChecker::instance().is_tencent_domain(sni)) {
                            ctx->is_direct = true;
                            std::string tag = GeoChecker::instance().query_domain(sni);
                            LOG_INFO("[TCP] Domain Detected: %s (Tag: %s). Direct.\n", sni.c_str(), tag.c_str());
                        } else {
                            // 特殊处理：如果域名以 .cn 结尾，强制走直连
                            bool is_cn_suffix = false;
                            if (sni.length() >= 3) {
                                std::string suffix = sni.substr(sni.length() - 3);
                                std::transform(suffix.begin(), suffix.end(), suffix.begin(), 
                                    [](unsigned char c){ return std::tolower(c); });
                                if (suffix == ".cn") is_cn_suffix = true;
                            }

                            if (is_cn_suffix) {
                                ctx->is_direct = true;
                                std::string tag = GeoChecker::instance().query_domain(sni);
                                LOG_INFO("[TCP] Domain Detected: %s (Tag: %s). Direct (.cn suffix).\n", sni.c_str(), tag.c_str());
                            } else {
                                if (!ctx->is_direct) {
                                    ctx->is_direct = false;
                                    std::string tag = GeoChecker::instance().query_domain(sni);
                                    LOG_INFO("[TCP] Domain Detected: %s (Tag: %s). Proxy.\n", sni.c_str(), tag.c_str());
                                }
                            }
                        }
                    }
                } else {
                    uint32_t ip = ctx->target.original_dst_ip;
                    
                    // IP Rules
                    RouteAction action = RuleManager::instance().match_ip(ntohl(ip));
                    if (action == RouteAction::DIRECT) ctx->is_direct = true;
                    else if (action == RouteAction::PROXY) ctx->is_direct = false;
                    else if (action == RouteAction::BLOCK) {
                        close_tcp_ctx(ctx);
                        return ERR_ABRT;
                    }
                    // Else use existing default (usually GeoChecker is_cn_ip checked at accept)
                    
                    std::string ip_str = std::to_string(ip & 0xFF) + "." +
                        std::to_string((ip >> 8) & 0xFF) + "." +
                        std::to_string((ip >> 16) & 0xFF) + "." +
                        std::to_string((ip >> 24) & 0xFF);
                    LOG_DEBUG("[TCP] No SNI/Host detected. Using IP-based decision (is_direct: %s) (ip: %s) \n", ctx->is_direct ? "true" : "false", ip_str.c_str());
                }
                connect_to_proxy_async(ctx);
            }
        }
    }
    pbuf_free(p);
    return ERR_OK;
}

err_t tcp_proxy_accept(void* arg, struct tcp_pcb* newpcb, err_t err) {
    uint16_t client_port = newpcb->remote_port;
    NatEntry target = NatTable::instance().get(client_port);
    if (target.original_dst_ip == 0) return ERR_ABRT;
    tcp_nagle_disable(newpcb);
    TcpCtx* ctx = new TcpCtx();
    ctx->client_pcb = newpcb;
    ctx->target = target;
    ctx->client_ip = newpcb->remote_ip.addr;
    ctx->client_port = newpcb->remote_port;

    // IP Check (RuleManager Priority)
    uint32_t dst_ip_h = ntohl(target.original_dst_ip);
    RouteAction ip_action = RuleManager::instance().match_ip(dst_ip_h);
    
    if (ip_action == RouteAction::BLOCK) {
        LOG_INFO("[TCP] IP Rule: Block %d.%d.%d.%d\n", 
            target.original_dst_ip & 0xFF, (target.original_dst_ip >> 8) & 0xFF, 
            (target.original_dst_ip >> 16) & 0xFF, (target.original_dst_ip >> 24) & 0xFF);
        delete ctx;
        return ERR_ABRT;
    } else if (ip_action == RouteAction::DIRECT) {
        ctx->is_direct = true;
        LOG_INFO("[TCP] IP Rule: Direct %d.%d.%d.%d\n", 
            target.original_dst_ip & 0xFF, (target.original_dst_ip >> 8) & 0xFF, 
            (target.original_dst_ip >> 16) & 0xFF, (target.original_dst_ip >> 24) & 0xFF);
    } else if (ip_action == RouteAction::PROXY) {
        ctx->is_direct = false;
        // Proceed
    } else {
        // Fallback to GeoIP
        if (GeoChecker::instance().is_cn_ip(dst_ip_h)) {
            ctx->is_direct = true;
            LOG_INFO("[TCP] IP Detected: %d.%d.%d.%d. Direct.\n",
                target.original_dst_ip & 0xFF, (target.original_dst_ip >> 8) & 0xFF, 
                (target.original_dst_ip >> 16) & 0xFF, (target.original_dst_ip >> 24) & 0xFF);
        }
    }

    tcp_arg(newpcb, ctx);
    tcp_recv(newpcb, tcp_client_recv);
    tcp_sent(newpcb, tcp_client_sent);
    tcp_err(newpcb, [](void* arg, err_t err) { 
        TcpCtx* c = (TcpCtx*)arg;
        c->client_pcb = NULL; 
        close_tcp_ctx(c); 
    });
    return ERR_OK;
}
