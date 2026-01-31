#include "proxy_tcp.h"
#include "worker.h"
#include "nat_table.h"
#include "tls_parser.h"
#include "app_config.h"
#include "lwip_handler.h"
#include "main_dispatcher.h"
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
    std::vector<uint8_t> sni_buffer;
    std::vector<uint8_t> upstream_data; // Pre-connect buffer
    
    // Zero-Copy Queue
    std::deque<std::vector<uint8_t>> tx_queue;
    size_t tx_acked_offset;   // Bytes acked in tx_queue.front()
    size_t tx_written_idx;    // Current buffer index being written to LwIP
    size_t tx_written_offset; // Bytes written in tx_queue[tx_written_idx]
    
    std::mutex data_mtx;
    Worker* worker;

    enum State { PRE_CONNECT, CONNECTING, HANDSHAKE_AUTH, HANDSHAKE_CONNECT, ESTABLISHED } state;

    TcpCtx() : client_pcb(NULL), proxy_socket(INVALID_SOCKET), closed(false), connected(false), read_paused(false), worker(NULL), state(PRE_CONNECT),
               tx_acked_offset(0), tx_written_idx(0), tx_written_offset(0) {
        sni_buffer.reserve(MAX_SNI_LEN);
        upstream_data.reserve(8192); 
    }
};

void close_tcp_ctx(TcpCtx* ctx);
void handle_proxy_read(TcpCtx* ctx);

// Internal helper to finalize cleanup on Main Thread
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

// Internal helper to stop socket on Worker Thread
void internal_close_on_worker(TcpCtx* ctx) {
    if (ctx->proxy_socket != INVALID_SOCKET) {
        ctx->worker->remove_socket(ctx->proxy_socket, [ctx]() {
            closesocket(ctx->proxy_socket);
            // Socket is gone, no more reads. Now safe to delete ctx on Main Thread.
            MainDispatcher::instance().queue_task([ctx]() {
                final_cleanup_on_main(ctx);
            });
        });
    } else {
        // No socket, just delete on Main Thread
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
        // Should not happen if connected, but fallback
        MainDispatcher::instance().queue_task([ctx]() {
            final_cleanup_on_main(ctx);
        });
    }
}

// Internal helper: Try to write pending buffers to LwIP (Zero-Copy)
void try_send_downstream(TcpCtx* ctx) {
    if (!ctx || ctx->closed || !ctx->client_pcb) return;

    while (ctx->tx_written_idx < ctx->tx_queue.size()) {
        auto& buf = ctx->tx_queue[ctx->tx_written_idx];
        
        // Safety check for offset
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

        // ZERO COPY WRITE: Pass 0 as copy flag
        // We guarantee 'buf' stays in tx_queue until Acked
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
    
    // NO AUTO RESUME HERE. 
    // Resume is handled in tcp_client_sent (ACK based flow control)
    // or if we simply failed to write due to MEM but now have space (rare in LwIP single thread without ack)
}

// Flow Control Callback (Main Thread)
err_t tcp_client_sent(void* arg, struct tcp_pcb* tpcb, u16_t len) {
    TcpCtx* ctx = (TcpCtx*)arg;
    if (!ctx || ctx->closed) return ERR_OK;

    // 1. Process Acks: Remove fully acked buffers from front
    while (len > 0 && !ctx->tx_queue.empty()) {
        auto& head = ctx->tx_queue.front();
        size_t unacked = head.size() - ctx->tx_acked_offset;
        
        if (len >= unacked) {
            len -= (u16_t)unacked;
            ctx->tx_queue.pop_front();
            ctx->tx_acked_offset = 0;
            // Adjust written index since we removed a buffer from front
            if (ctx->tx_written_idx > 0) ctx->tx_written_idx--;
        } else {
            ctx->tx_acked_offset += len;
            len = 0;
        }
    }

    // 2. Try to send more pending data
    try_send_downstream(ctx);
    
    return ERR_OK;
}

// Established state handler (Worker Thread) - DOWNSTREAM ASYNC
void handle_proxy_read(TcpCtx* ctx) {
    if (ctx->closed) return;
    
    // Optimization: Use thread_local buffer to avoid allocation/zero-fill overhead per read
    thread_local std::vector<uint8_t> read_buf(262144);
    
    int r = recv(ctx->proxy_socket, (char*)read_buf.data(), (int)read_buf.size(), 0);
    
    if (r > 0) {
        // Copy only actual data. vector(iter, iter) is more efficient than resize() on a fresh zeroed vector.
        std::vector<uint8_t> data(read_buf.begin(), read_buf.begin() + r);
        
        // Use mutable to allow moving 'd' into tx_queue
        MainDispatcher::instance().queue_task([ctx, d = std::move(data)]() mutable {
            // Running on Main Thread
            std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
            if (ctx->client_pcb && !ctx->closed) {
                // Append to Zero-Copy Queue
                ctx->tx_queue.push_back(std::move(d));
                
                // Try to write to LwIP
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
    char buf[512];
    int r = recv(ctx->proxy_socket, buf, sizeof(buf), 0);
    
    if (r > 0) {
        if (ctx->state == TcpCtx::HANDSHAKE_AUTH) {
            // SOCKS5 Auth Response: 05 00
            if (r >= 2 && buf[0] == 0x05 && buf[1] == 0x00) {
                // Auth OK. Send Connect Request.
                // Re-parse target to construct request
                std::string sni = parse_tls_sni(ctx->sni_buffer.data(), ctx->sni_buffer.size());
                std::string http_host;
                if (sni.empty()) http_host = parse_http_host(ctx->sni_buffer.data(), ctx->sni_buffer.size());

                std::vector<uint8_t> req;
                req.push_back(0x05); // Ver
                req.push_back(0x01); // Cmd: Connect
                req.push_back(0x00); // Rsv
                
                if (!sni.empty()) {
                    req.push_back(0x03); // Domain
                    req.push_back((uint8_t)sni.length());
                    req.insert(req.end(), sni.begin(), sni.end());
                } else if (!http_host.empty()) {
                    req.push_back(0x03); // Domain
                    req.push_back((uint8_t)http_host.length());
                    req.insert(req.end(), http_host.begin(), http_host.end());
                } else {
                    req.push_back(0x01); // IPv4
                    uint32_t ip = ctx->target.original_dst_ip;
                    // IP is stored in network order in target (from raw packet)? 
                    // NatEntry original_dst_ip is uint32_t. In lwip_handler, it is ip->dest.addr.
                    // ip->dest.addr is Network Order.
                    // So we can just copy bytes.
                    req.push_back(ip & 0xFF);
                    req.push_back((ip >> 8) & 0xFF);
                    req.push_back((ip >> 16) & 0xFF);
                    req.push_back((ip >> 24) & 0xFF);
                }
                
                // Port: Network Order (2 bytes)
                uint16_t port = ctx->target.original_dst_port; 
                req.push_back(port & 0xFF);
                req.push_back((port >> 8) & 0xFF);
                
                send(ctx->proxy_socket, (const char*)req.data(), (int)req.size(), 0);
                ctx->state = TcpCtx::HANDSHAKE_CONNECT;
            } else {
                close_tcp_ctx(ctx);
            }
        } else if (ctx->state == TcpCtx::HANDSHAKE_CONNECT) {
            // SOCKS5 Connect Response: 05 00 ...
            if (r >= 4 && buf[0] == 0x05 && buf[1] == 0x00) {
                 {
                    std::lock_guard<std::mutex> lock(ctx->data_mtx);
                    if (!ctx->upstream_data.empty()) {
                         send(ctx->proxy_socket, (const char*)ctx->upstream_data.data(), (int)ctx->upstream_data.size(), 0);
                         ctx->upstream_data.clear();
                    }
                    ctx->connected = true;
                    ctx->state = TcpCtx::ESTABLISHED;
                }
                
                ctx->worker->add_socket(
                    ctx->proxy_socket,
                    [ctx]() { handle_proxy_read(ctx); },
                    nullptr,
                    [ctx]() { close_tcp_ctx(ctx); }
                );
            } else {
                close_tcp_ctx(ctx);
            }
        }
    } else {
        close_tcp_ctx(ctx);
    }
}

void handle_proxy_connect(TcpCtx* ctx) {
    if (ctx->closed) return;

    int err = 0; int len = sizeof(err);
    if (getsockopt(ctx->proxy_socket, SOL_SOCKET, SO_ERROR, (char*)&err, &len) == SOCKET_ERROR) {
        err = WSAGetLastError();
    }
    
    if (err != 0) {
        close_tcp_ctx(ctx);
        return;
    }

    // Initiate SOCKS5 Handshake: Auth Methods
    // 0x05: Ver, 0x01: NMethods, 0x00: No Auth
    uint8_t auth_req[] = { 0x05, 0x01, 0x00 };
    
    int sent = send(ctx->proxy_socket, (const char*)auth_req, sizeof(auth_req), 0);
    if (sent == SOCKET_ERROR) {
         if (WSAGetLastError() != WSAEWOULDBLOCK) {
             close_tcp_ctx(ctx);
             return;
         }
         close_tcp_ctx(ctx); 
         return;
    }

    ctx->state = TcpCtx::HANDSHAKE_AUTH;

    ctx->worker->add_socket(
        ctx->proxy_socket,
        [ctx]() { handle_handshake_read(ctx); }, 
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
        if (ctx->proxy_socket == INVALID_SOCKET) {
            close_tcp_ctx(ctx);
            return;
        }

        u_long mode = 1;
        if (ioctlsocket(ctx->proxy_socket, FIONBIO, &mode) != 0) {
            close_tcp_ctx(ctx);
            return;
        }

        struct WinSockAddr {
            short sin_family;
            unsigned short sin_port;
            struct { unsigned long S_addr; } sin_addr;
            char sin_zero[8];
        } addr;

        memset(&addr, 0, sizeof(addr));
        
        unsigned int a, b, c, d;
        if (sscanf_s(PROXY_IP, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            addr.sin_addr.S_addr = (a) | (b << 8) | (c << 16) | (d << 24);
        } else {
            addr.sin_addr.S_addr = 0x0100007F; 
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(PROXY_PORT);

        // IOCP Update: Use connect_async
        ctx->worker->connect_async(
            ctx->proxy_socket, 
            *(sockaddr_in*)&addr, 
            [ctx]() {
                // On Connect Success
                handle_proxy_connect(ctx); 
            }
        );
    });
}

err_t tcp_client_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    TcpCtx* ctx = (TcpCtx*)arg;
    if (!ctx || ctx->closed) {
        if (p) pbuf_free(p);
        return ERR_OK;
    }

    if (!p) { 
        // LwIP indicates connection closed
        close_tcp_ctx(ctx); 
        return ERR_OK; 
    }
    tcp_recved(tpcb, p->tot_len);

    if (ctx->connected && ctx->worker) {
        std::vector<uint8_t> data;
        data.reserve(p->tot_len);
        for (struct pbuf* q = p; q != NULL; q = q->next) {
            data.insert(data.end(), (uint8_t*)q->payload, (uint8_t*)q->payload + q->len);
        }

        ctx->worker->queue_task([ctx, d = std::move(data)]() {
            if (ctx->closed) return;
            if (ctx->proxy_socket != INVALID_SOCKET) {
                send(ctx->proxy_socket, (const char*)d.data(), (int)d.size(), 0);
            }
        });

    } else {
        std::lock_guard<std::mutex> lock(ctx->data_mtx);
        
        for (struct pbuf* q = p; q != NULL; q = q->next) {
            uint8_t* d = (uint8_t*)q->payload;
            ctx->upstream_data.insert(ctx->upstream_data.end(), d, d + q->len);
            
            if (ctx->state == TcpCtx::PRE_CONNECT) {
                if (ctx->sni_buffer.size() < MAX_SNI_LEN) {
                    size_t to_copy = (std::min)((size_t)q->len, (size_t)(MAX_SNI_LEN - ctx->sni_buffer.size()));
                    ctx->sni_buffer.insert(ctx->sni_buffer.end(), d, d + to_copy);
                }
            }
        }

        if (ctx->connected) {
            if (ctx->proxy_socket != INVALID_SOCKET) {
                 send(ctx->proxy_socket, (const char*)ctx->upstream_data.data(), (int)ctx->upstream_data.size(), 0);
                 ctx->upstream_data.clear();
            }
        } else {
            if (ctx->state == TcpCtx::PRE_CONNECT) {
                bool ready = false;
                if (ctx->sni_buffer.size() >= MAX_SNI_LEN) ready = true;
                else if (ctx->sni_buffer.size() >= 5) {
                    if (ctx->sni_buffer[0] != 0x16) {
                        // Not TLS. Try HTTP Host.
                        if (is_http_start(ctx->sni_buffer.data(), ctx->sni_buffer.size())) {
                            std::string host = parse_http_host(ctx->sni_buffer.data(), ctx->sni_buffer.size());
                            if (!host.empty()) {
                                ready = true; // Found Host header
                            } else {
                                // Looks like HTTP but no Host header yet.
                                // If buffer is large, give up.
                                if (ctx->sni_buffer.size() > 1024) ready = true; 
                            }
                        } else {
                            // Not TLS, Not HTTP start -> Unknown/Raw -> Fallback to IP
                            ready = true; 
                        }
                    } else { 
                        // TLS
                        uint16_t tls_len = ((uint16_t)ctx->sni_buffer[3] << 8) | ctx->sni_buffer[4];
                        if (ctx->sni_buffer.size() >= (size_t)5 + tls_len) ready = true; 
                    }
                }
                
                if (ready) {
                    connect_to_proxy_async(ctx);
                }
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
    
    // Disable Nagle algorithm to reduce latency (especially for handshake)
    tcp_nagle_disable(newpcb);

    TcpCtx* ctx = new TcpCtx();
    ctx->client_pcb = newpcb;
    ctx->target = target;
    tcp_arg(newpcb, ctx);
    tcp_recv(newpcb, tcp_client_recv);
    tcp_sent(newpcb, tcp_client_sent);
    
    tcp_err(newpcb, [](void* arg, err_t err) { 
        TcpCtx* c = (TcpCtx*)arg;
        c->client_pcb = NULL; 
        // Trigger close from Main Thread side
        close_tcp_ctx(c); 
    });
    return ERR_OK;
}