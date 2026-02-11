#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include "lwip/ip_addr.h"
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
#include "connection_pool.h"
#include <atomic>
#include <mutex>
#include <vector>
#include <deque>
#include <string>
#include <algorithm>
#include <memory>
#include <chrono>

const size_t MAX_BATCH_SIZE = 64 * 1024; // 64KB
const int MAX_DELAY_MS = 10; // 10ms

struct TcpCtx;
typedef std::shared_ptr<TcpCtx> TcpCtxPtr;

// --- TCP Logic with Worker Pool ---
struct TcpCtx : public std::enable_shared_from_this<TcpCtx> {
    struct tcp_pcb* client_pcb;
    SOCKET proxy_socket;
    std::atomic<bool> closed;
    std::atomic<bool> connected;
    bool read_paused;
    NatEntry target;
    
    // Pointer to the heap-allocated shared_ptr held by LwIP
    void* lwip_arg; 
    
    // Client Info for Logging
    uint32_t client_ip;
    uint16_t client_port;

    bool is_direct; 
    
    // Graceful Shutdown Flag
    bool upstream_eof; 

    // Sniffing
    std::vector<uint8_t> sni_buffer;
    std::vector<uint8_t> upstream_data; 
    std::string detected_domain;        
    
    // Downstream Queue (Proxy -> Phone)
    std::deque<std::vector<uint8_t>> tx_queue;
    size_t tx_acked_offset;   
    size_t tx_written_idx;    
    size_t tx_written_offset; 
    
    // Upstream Queue (Phone -> Proxy)
    std::deque<std::vector<uint8_t>> upstream_queue;
    size_t upstream_offset;
    bool upstream_busy;

    // Downlink Batching (Proxy -> Main Thread)
    std::vector<uint8_t> downstream_buffer;
    std::chrono::steady_clock::time_point last_downstream_flush_time;

    std::mutex data_mtx;
    Worker* worker;

    enum State { PRE_CONNECT, CONNECTING, HANDSHAKE, ESTABLISHED } state;

    TcpCtx() : client_pcb(NULL), proxy_socket(INVALID_SOCKET), closed(false), connected(false), read_paused(false), worker(NULL), state(PRE_CONNECT),
               tx_acked_offset(0), tx_written_idx(0), tx_written_offset(0), 
               upstream_offset(0), upstream_busy(false), lwip_arg(nullptr), upstream_eof(false),
               client_ip(0), client_port(0), is_direct(false) {
        sni_buffer.reserve(g_config.max_sni_len);
        upstream_data.reserve(8192); 
        downstream_buffer.reserve(MAX_BATCH_SIZE);
        last_downstream_flush_time = std::chrono::steady_clock::now();
    }
};

void close_tcp_ctx(TcpCtxPtr ctx);
void handle_proxy_read(TcpCtxPtr ctx);
void handle_proxy_write(TcpCtxPtr ctx, int bytes);
void connect_to_proxy_async(TcpCtxPtr ctx);
void try_send_upstream(TcpCtxPtr ctx); 

void flush_downstream_buffer(TcpCtxPtr ctx) {
    if (ctx->downstream_buffer.empty()) return;

    MainDispatcher::instance().queue_task([ctx, d = std::move(ctx->downstream_buffer)]() mutable {
        if (ctx->client_pcb && !ctx->closed) {
            ctx->tx_queue.push_back(std::move(d));
            try_send_downstream(ctx);
        }
    });

    ctx->downstream_buffer.clear();
    ctx->downstream_buffer.reserve(MAX_BATCH_SIZE);
    ctx->last_downstream_flush_time = std::chrono::steady_clock::now();
}

void check_and_flush_downstream(TcpCtxPtr ctx) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - ctx->last_downstream_flush_time).count();

    if (ctx->downstream_buffer.size() >= MAX_BATCH_SIZE || (elapsed >= MAX_DELAY_MS && !ctx->downstream_buffer.empty())) {
        flush_downstream_buffer(ctx);
    }
}

// Cleanup function running on Main Thread
void final_cleanup_on_main(void* arg) {
    TcpCtxPtr* ptr = (TcpCtxPtr*)arg;
    if (!ptr) return;
    
    auto ctx = *ptr;
    
    if (ctx->client_pcb) {
        tcp_arg(ctx->client_pcb, NULL);
        tcp_recv(ctx->client_pcb, NULL);
        tcp_sent(ctx->client_pcb, NULL);
        tcp_err(ctx->client_pcb, NULL);
        tcp_close(ctx->client_pcb);
        ctx->client_pcb = NULL;
    }
    
    delete ptr; 
}

void internal_close_on_worker(TcpCtxPtr ctx) {
    if (ctx->proxy_socket != INVALID_SOCKET) {
        ctx->worker->remove_socket(ctx->proxy_socket, [ctx]() {
            // Note: Worker now handles closesocket(ctx->proxy_socket) automatically
            // when pending_io reached zero.
            
            void* arg = ctx->lwip_arg;
            if (arg) {
                MainDispatcher::instance().queue_task([arg]() {
                    final_cleanup_on_main(arg);
                });
            }
        });
    } else {
        void* arg = ctx->lwip_arg;
        if (arg) {
            MainDispatcher::instance().queue_task([arg]() {
                final_cleanup_on_main(arg);
            });
        }
    }
}

void close_tcp_ctx(TcpCtxPtr ctx) {
    if (!ctx || ctx->closed.exchange(true)) return;

    if (ctx->worker) {
        ctx->worker->queue_task([ctx]() {
            internal_close_on_worker(ctx);
        });
    } else {
        void* arg = ctx->lwip_arg;
        if (arg) {
            MainDispatcher::instance().queue_task([arg]() {
                final_cleanup_on_main(arg);
            });
        }
    }
}

// --- Downstream (Proxy -> Phone) ---
void try_send_downstream(TcpCtxPtr ctx) {
    if (!ctx || ctx->closed || !ctx->client_pcb) return;

    while (ctx->tx_written_idx < ctx->tx_queue.size()) {
        auto& buf = ctx->tx_queue[ctx->tx_written_idx];
        
        if (ctx->tx_written_offset >= buf.size()) {
            ctx->tx_written_idx++;
            ctx->tx_written_offset = 0;
            continue;
        }

        size_t limit = tcp_sndbuf(ctx->client_pcb);
        if (limit == 0) break; 

        size_t remaining = buf.size() - ctx->tx_written_offset;
        size_t chunk_sz = (std::min)(limit, remaining);
        if (chunk_sz > 0xFFFF) chunk_sz = 0xFFFF;
        u16_t chunk = (u16_t)chunk_sz;
        if (chunk == 0) break;

        err_t err = tcp_write(ctx->client_pcb, 
                              buf.data() + ctx->tx_written_offset, 
                              chunk, 
                              1); 
                              
        if (err == ERR_OK) {
            ctx->tx_written_offset += chunk;
            if (ctx->tx_written_offset >= buf.size()) {
                ctx->tx_written_idx++;
                ctx->tx_written_offset = 0;
            }
        } else if (err == ERR_MEM) {
            break;
        } else {
            close_tcp_ctx(ctx);
            return;
        }
    }
    
    if (ctx->client_pcb) {
        tcp_output(ctx->client_pcb);
    }

    // Graceful Shutdown Check
    if (ctx->upstream_eof && ctx->tx_written_idx >= ctx->tx_queue.size()) {
        close_tcp_ctx(ctx);
    }
}

err_t tcp_client_sent(void* arg, struct tcp_pcb* tpcb, u16_t len) {
    TcpCtxPtr* ptr = (TcpCtxPtr*)arg;
    if (!ptr) return ERR_OK;
    auto ctx = *ptr;
    
    if (ctx->closed) return ERR_OK;

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

void handle_proxy_read(TcpCtxPtr ctx) {
    if (ctx->closed) return;
    
    char buf[65536];
    bool socket_closed = false;

    while (true) {
        int r = recv(ctx->proxy_socket, buf, sizeof(buf), 0);
        if (r > 0) {
            TrafficManager::instance().report_proxy_rx(r, ctx->is_direct);
            ctx->downstream_buffer.insert(ctx->downstream_buffer.end(), (uint8_t*)buf, (uint8_t*)buf + r);
            if (ctx->downstream_buffer.size() >= MAX_BATCH_SIZE) break; 
        } else if (r == 0) {
            socket_closed = true;
            break;
        } else {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                close_tcp_ctx(ctx);
            }
            break;
        }
    }

    check_and_flush_downstream(ctx);

    if (socket_closed) {
        flush_downstream_buffer(ctx);
        ctx->worker->remove_socket(ctx->proxy_socket, nullptr); 
        ctx->proxy_socket = INVALID_SOCKET; 
        
        MainDispatcher::instance().queue_task([ctx]() {
            if (ctx->closed) return;
            ctx->upstream_eof = true;
            try_send_downstream(ctx);
        });
    }
}

// --- Upstream Async Write Callback ---
void handle_proxy_write(TcpCtxPtr ctx, int bytes) {
    if (ctx->closed) return;
    
    ctx->upstream_busy = false;

    if (bytes <= 0) {
        if (bytes < 0) { 
             LOG_INFO("[TCP] Async write failed: %d. Closing.", bytes);
             close_tcp_ctx(ctx);
        }
        return;
    }

    TrafficManager::instance().report_proxy_tx(bytes, ctx->is_direct);
    ctx->upstream_offset += bytes;
    
    // Check if current chunk is done
    if (!ctx->upstream_queue.empty()) {
        auto& head = ctx->upstream_queue.front();
        if (ctx->upstream_offset >= head.size()) {
            ctx->upstream_queue.pop_front();
            ctx->upstream_offset = 0;
        }
    }

    try_send_upstream(ctx);
}

// --- Upstream (Phone -> Proxy) ---
void try_send_upstream(TcpCtxPtr ctx) {
    if (ctx->closed || ctx->proxy_socket == INVALID_SOCKET) return;
    if (ctx->state != TcpCtx::ESTABLISHED && ctx->state != TcpCtx::HANDSHAKE) return;

    if (ctx->upstream_busy) return;
    if (ctx->upstream_queue.empty()) return;

    auto& data = ctx->upstream_queue.front();
    if (ctx->upstream_offset >= data.size()) {
        ctx->upstream_queue.pop_front();
        ctx->upstream_offset = 0;
        try_send_upstream(ctx); // Recurse for next packet
        return;
    }

    char* ptr = (char*)data.data() + ctx->upstream_offset;
    int remaining = (int)(data.size() - ctx->upstream_offset);

    ctx->upstream_busy = true;
    bool scheduled = ctx->worker->send_async(ctx->proxy_socket, ptr, remaining);
    
    if (!scheduled) {
        ctx->upstream_busy = false;
    }
}

void handle_handshake_read(TcpCtxPtr ctx) {
    if (ctx->closed) return;
    char buf[4096];
    int r = recv(ctx->proxy_socket, buf, sizeof(buf), 0);
    
    if (r > 0) {
        TrafficManager::instance().report_proxy_rx(r, false); 
        std::string s(buf, r);
        size_t header_end = s.find("\r\n\r\n");
        
        if (header_end != std::string::npos) {
            std::string header = s.substr(0, header_end);
            if (header.find("200") != std::string::npos) {
                uint32_t cip = ctx->client_ip;
                uint32_t dip = ctx->target.original_dst_ip;
                if (ctx->detected_domain.empty()) {
                    LOG_INFO("[TCP] Proxy %d.%d.%d.%d:%-5d -> %d.%d.%d.%d:%d",
                        cip & 0xFF, (cip >> 8) & 0xFF, (cip >> 16) & 0xFF, (cip >> 24) & 0xFF, ctx->client_port,
                        dip & 0xFF, (dip >> 8) & 0xFF, (dip >> 16) & 0xFF, (dip >> 24) & 0xFF, ctx->target.original_dst_port);
                } else {
                    LOG_INFO("[TCP] Proxy %d.%d.%d.%d:%-5d -> %s:%d",
                        cip & 0xFF, (cip >> 8) & 0xFF, (cip >> 16) & 0xFF, (cip >> 24) & 0xFF, ctx->client_port,
                        ctx->detected_domain.c_str(), ctx->target.original_dst_port);
                }
                
                {
                    std::lock_guard<std::mutex> lock(ctx->data_mtx);
                    ctx->connected = true;
                    ctx->state = TcpCtx::ESTABLISHED;
                    if (!ctx->upstream_data.empty()) {
                        ctx->upstream_queue.push_back(std::move(ctx->upstream_data));
                        ctx->upstream_data.clear();
                    }
                }
                
                try_send_upstream(ctx);

                size_t payload_start = header_end + 4;
                if (payload_start < (size_t)r) {
                    std::vector<uint8_t> extra_data((uint8_t*)(buf + payload_start), (uint8_t*)(buf + r));
                    MainDispatcher::instance().queue_task([ctx, d = std::move(extra_data)]() mutable {
                        if (ctx->client_pcb) {
                            ctx->tx_queue.push_back(std::move(d));
                            try_send_downstream(ctx);
                        }
                    });
                }
                
                ctx->worker->add_socket(
                    ctx->proxy_socket,
                    [ctx](char*, int, sockaddr_in*) { handle_proxy_read(ctx); },
                    [ctx](int bytes) { handle_proxy_write(ctx, bytes); },
                    [ctx]() { close_tcp_ctx(ctx); }
                );
                ctx->worker->set_socket_user_data(ctx->proxy_socket, new std::shared_ptr<TcpCtx>(ctx));
            } else {
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

void handle_proxy_connect(TcpCtxPtr ctx) {
    if (ctx->closed) return;

    int err = 0; int len = sizeof(err);
    getsockopt(ctx->proxy_socket, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
    if (err != 0) {
        close_tcp_ctx(ctx);
        return;
    }

    if (ctx->is_direct) {
        uint32_t cip = ctx->client_ip;
        uint32_t dip = ctx->target.original_dst_ip;
        if (ctx->detected_domain.empty()) {
            LOG_INFO("[TCP] Direct %d.%d.%d.%d:%-5d -> %d.%d.%d.%d:%d",
                cip & 0xFF, (cip >> 8) & 0xFF, (cip >> 16) & 0xFF, (cip >> 24) & 0xFF, ctx->client_port,
                dip & 0xFF, (dip >> 8) & 0xFF, (dip >> 16) & 0xFF, (dip >> 24) & 0xFF, ctx->target.original_dst_port);
        } else {
            LOG_INFO("[TCP] Direct %d.%d.%d.%d:%-5d -> %s:%d",
                cip & 0xFF, (cip >> 8) & 0xFF, (cip >> 16) & 0xFF, (cip >> 24) & 0xFF, ctx->client_port,
                ctx->detected_domain.c_str(), ctx->target.original_dst_port);
        }
        {
            std::lock_guard<std::mutex> lock(ctx->data_mtx);
            ctx->connected = true;
            ctx->state = TcpCtx::ESTABLISHED;
            if (!ctx->upstream_data.empty()) {
                ctx->upstream_queue.push_back(std::move(ctx->upstream_data));
                ctx->upstream_data.clear();
            }
        }
        try_send_upstream(ctx);
        ctx->worker->add_socket(
            ctx->proxy_socket,
            [ctx](char*, int, sockaddr_in*) { handle_proxy_read(ctx); },
            [ctx](int bytes) { handle_proxy_write(ctx, bytes); },
            [ctx]() { close_tcp_ctx(ctx); }
        );
        ctx->worker->set_socket_user_data(ctx->proxy_socket, new std::shared_ptr<TcpCtx>(ctx));
        return;
    }

    uint32_t ip = ctx->target.original_dst_ip;
    std::string sni = ctx->detected_domain;
    std::string ip_str = std::to_string(ip & 0xFF) + "." + std::to_string((ip >> 8) & 0xFF) + "."
                        + std::to_string((ip >> 16) & 0xFF) + "." + std::to_string((ip >> 24) & 0xFF);
    std::string host = !sni.empty() ? sni : ip_str;
    char cmd[1024];
    uint16_t port = ctx->target.original_dst_port;
    
    sprintf_s(cmd, "CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n", host.c_str(), port, host.c_str());
    int cmd_len = (int)strlen(cmd);
    int sent = send(ctx->proxy_socket, cmd, cmd_len, 0);
    if (sent == SOCKET_ERROR || sent < cmd_len) {
         close_tcp_ctx(ctx); return;
    }

    TrafficManager::instance().report_proxy_tx(sent, false); 
    ctx->state = TcpCtx::HANDSHAKE;
    ctx->worker->add_socket(
        ctx->proxy_socket,
        [ctx](char*, int, sockaddr_in*) { handle_handshake_read(ctx); }, 
        nullptr, 
        [ctx]() { close_tcp_ctx(ctx); }
    );
}

void connect_to_proxy_async(TcpCtxPtr ctx) {
    if (!ctx->worker) {
        // Distribute workers by client source port instead of destination port
        // to avoid all connections to the same server being handled by one worker.
        ctx->worker = WorkerPool::instance().get_worker(ctx->client_port);
        if (!ctx->worker) ctx->worker = WorkerPool::instance().get_next_worker();
    }
    ctx->state = TcpCtx::CONNECTING;
    ctx->worker->queue_task([ctx]() {
        if (ctx->closed) return;

        // Try to acquire from pool for direct connections
        if (ctx->is_direct) {
            uint32_t ip = ctx->target.original_dst_ip;
            uint16_t port = ctx->target.original_dst_port;
            std::string dest = std::to_string(ip & 0xFF) + "." + std::to_string((ip >> 8) & 0xFF) + "."
                             + std::to_string((ip >> 16) & 0xFF) + "." + std::to_string((ip >> 24) & 0xFF)
                             + ":" + std::to_string(port);
            
            SOCKET s = ConnectionPool::instance().acquire(dest);
            if (s != INVALID_SOCKET) {
                ctx->proxy_socket = s;
                // Already connected, directly proceed to the next step
                handle_proxy_connect(ctx);
                return;
            }
        }

        // Fallback: create a new connection
        ctx->proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (ctx->proxy_socket == INVALID_SOCKET) { close_tcp_ctx(ctx); return; }
        
        BOOL keepAlive = TRUE;
        setsockopt(ctx->proxy_socket, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepAlive, sizeof(keepAlive));
        int bufSize = 4 * 1024 * 1024; 
        setsockopt(ctx->proxy_socket, SOL_SOCKET, SO_SNDBUF, (char*)&bufSize, sizeof(bufSize));
        setsockopt(ctx->proxy_socket, SOL_SOCKET, SO_RCVBUF, (char*)&bufSize, sizeof(bufSize));

        u_long mode = 1; ioctlsocket(ctx->proxy_socket, FIONBIO, &mode);
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        
        unsigned int a, b, c, d;
        if (ctx->is_direct) {
            addr.sin_addr.S_un.S_addr = ctx->target.original_dst_ip;
            addr.sin_port = htons(ctx->target.original_dst_port);
        } else {
            if (sscanf_s(g_config.proxy_ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                addr.sin_addr.S_un.S_addr = (a) | (b << 8) | (c << 16) | (d << 24);
            } else { addr.sin_addr.S_un.S_addr = 0x0100007F; } 
            addr.sin_port = htons(g_config.proxy_port);
        }
        ctx->worker->connect_async(ctx->proxy_socket, addr, [ctx]() { handle_proxy_connect(ctx); });
    });
}

err_t tcp_client_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    TcpCtxPtr* ptr = (TcpCtxPtr*)arg;
    if (!ptr) { if (p) pbuf_free(p); return ERR_OK; }
    auto ctx = *ptr;
    if (!ctx || ctx->closed) { if (p) pbuf_free(p); return ERR_OK; }
    if (!p) { close_tcp_ctx(ctx); return ERR_OK; }

    if (ctx->connected && ctx->worker) {
        std::vector<uint8_t> data;
        data.reserve(p->tot_len);
        for (struct pbuf* q = p; q != NULL; q = q->next) {
            data.insert(data.end(), (uint8_t*)q->payload, (uint8_t*)q->payload + q->len);
        }
        
        size_t left = p->tot_len;
        while (left > 0) {
            u16_t chunk = (u16_t)(std::min)(left, (size_t)0xFFFF);
            tcp_recved(tpcb, chunk);
            left -= chunk;
        }
        
        ctx->worker->queue_task([ctx, d = std::move(data)]() {
            if (ctx->closed) return;
            ctx->upstream_queue.push_back(std::move(d));
            try_send_upstream(ctx);
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
        tcp_recved(tpcb, p->tot_len);
        
        if (ctx->state == TcpCtx::PRE_CONNECT) {
            // Captive Portal Check
            if (ctx->target.original_dst_port == 80 && ctx->sni_buffer.size() > 10) {
                ip4_addr_t gw_addr;
                ip4addr_aton(g_config.tap_gateway.c_str(), &gw_addr);
                bool is_generate_204 = strncmp((char*)ctx->sni_buffer.data(), "GET /generate_204", 17) == 0;
                bool is_gateway_req = (ctx->target.original_dst_ip == gw_addr.addr);

                if (is_generate_204 || is_gateway_req) {
                    LOG_INFO("[TCP] Captive portal request detected. Sending 204 response.");
                    const char* response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                    tcp_write(tpcb, response, (u16_t)strlen(response), TCP_WRITE_FLAG_COPY);
                    tcp_output(tpcb);
                    tcp_close(tpcb);
                    pbuf_free(p);
                    return ERR_OK;
                }
            }

            bool ready = false;
            if (ctx->sni_buffer.size() >= 5 && ctx->sni_buffer[0] == 0x16) {
                uint16_t tls_len = ((uint16_t)ctx->sni_buffer[3] << 8) | ctx->sni_buffer[4];
                if (ctx->sni_buffer.size() >= (size_t)5 + tls_len) ready = true; 
            }
            else if (is_http_start(ctx->sni_buffer.data(), ctx->sni_buffer.size())) {
                std::string host = parse_http_host(ctx->sni_buffer.data(), ctx->sni_buffer.size());
                if (!host.empty()) ready = true;
                else if (ctx->sni_buffer.size() > 1024) ready = true;
            }
            else if (ctx->sni_buffer.size() > 64) ready = true;
            
            if (ready) {
                std::string sni = parse_tls_sni(ctx->sni_buffer.data(), ctx->sni_buffer.size());
                if (sni.empty()) sni = parse_http_host(ctx->sni_buffer.data(), ctx->sni_buffer.size());
                if (!sni.empty()) {
                    ctx->detected_domain = sni;
                    RouteAction action = RuleManager::instance().match_domain(sni);
                    if (action == RouteAction::DIRECT) ctx->is_direct = true;
                    else if (action == RouteAction::PROXY) ctx->is_direct = false;
                    else if (action == RouteAction::BLOCK) { close_tcp_ctx(ctx); return ERR_ABRT; }
                    else {
                        if (GeoChecker::instance().is_cn_domain(sni) || GeoChecker::instance().is_tencent_domain(sni)) ctx->is_direct = true;
                        else if (!ctx->is_direct) ctx->is_direct = false;
                    }
                } else {
                    uint32_t ip = ctx->target.original_dst_ip;
                    RouteAction action = RuleManager::instance().match_ip(ntohl(ip));
                    if (action == RouteAction::DIRECT) ctx->is_direct = true;
                    else if (action == RouteAction::BLOCK) { close_tcp_ctx(ctx); return ERR_ABRT; }
                }
                connect_to_proxy_async(ctx);
            }
        }
    }
    pbuf_free(p);
    return ERR_OK;
}

err_t tcp_proxy_accept(void* arg, struct tcp_pcb* newpcb, err_t err) {
    if (!newpcb) return ERR_MEM;

    uint16_t client_port = newpcb->remote_port;
    NatEntry target = NatTable::instance().get(newpcb->remote_ip.addr, client_port);
    if (target.original_dst_ip == 0) return ERR_ABRT;
    tcp_nagle_disable(newpcb);
    
    auto ctx = std::make_shared<TcpCtx>();
    ctx->client_pcb = newpcb;
    ctx->target = target;
    ctx->client_ip = newpcb->remote_ip.addr;
    ctx->client_port = newpcb->remote_port;

    TcpCtxPtr* ptr = new TcpCtxPtr(ctx);
    ctx->lwip_arg = ptr;

    uint32_t dst_ip_h = ntohl(target.original_dst_ip);
    RouteAction ip_action = RuleManager::instance().match_ip(dst_ip_h);
    if (ip_action == RouteAction::BLOCK) { delete ptr; return ERR_ABRT; }
    else if (ip_action == RouteAction::DIRECT) ctx->is_direct = true;
    else if (ip_action == RouteAction::PROXY) ctx->is_direct = false;
    else { if (GeoChecker::instance().is_cn_ip(dst_ip_h)) ctx->is_direct = true; }

    tcp_arg(newpcb, ptr);
    tcp_recv(newpcb, tcp_client_recv);
    tcp_sent(newpcb, tcp_client_sent);
    tcp_err(newpcb, [](void* arg, err_t err) { 
        TcpCtxPtr* ptr = (TcpCtxPtr*)arg;
        if (ptr) { auto ctx = *ptr; ctx->client_pcb = NULL; close_tcp_ctx(ctx); }
    });
    return ERR_OK;
}

void proxy_tcp_periodic_check(void* user_data) {
    if (!user_data) return;
    auto ctx = *(std::shared_ptr<TcpCtx>*)user_data;
    if (ctx) {
        check_and_flush_downstream(ctx);
    }
}
