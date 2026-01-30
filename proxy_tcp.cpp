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
#include <string>
#include <algorithm>

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
    std::vector<uint8_t> downstream_pending; // Pending data for LwIP
    std::mutex data_mtx;
    Worker* worker;

    enum State { PRE_CONNECT, CONNECTING, HANDSHAKE, ESTABLISHED } state;

    TcpCtx() : client_pcb(NULL), proxy_socket(INVALID_SOCKET), closed(false), connected(false), read_paused(false), worker(NULL), state(PRE_CONNECT) {
        sni_buffer.reserve(MAX_SNI_LEN);
        upstream_data.reserve(8192); 
        downstream_pending.reserve(262144);
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

// Flow Control Callback (Main Thread)
err_t tcp_client_sent(void* arg, struct tcp_pcb* tpcb, u16_t len) {
    TcpCtx* ctx = (TcpCtx*)arg;
    if (!ctx || ctx->closed) return ERR_OK;

    // Retry pending data
    if (!ctx->downstream_pending.empty()) {
        u16_t limit = tcp_sndbuf(tpcb);
        if (limit > 0) {
             size_t chunk = (std::min)((size_t)limit, ctx->downstream_pending.size());
             if (chunk > 0xffff) chunk = 0xffff; // Safety
             if (tcp_write(tpcb, ctx->downstream_pending.data(), (u16_t)chunk, 1) == ERR_OK) {
                 tcp_output(tpcb);
                 ctx->downstream_pending.erase(ctx->downstream_pending.begin(), ctx->downstream_pending.begin() + chunk);
             }
        }
    }

    if (ctx->read_paused && ctx->worker && ctx->downstream_pending.empty()) {
        if (tcp_sndbuf(tpcb) > 0) {
            ctx->read_paused = false;
            ctx->worker->queue_task([ctx]() {
                // Re-enable READ on Worker
                if (ctx->proxy_socket != INVALID_SOCKET) {
                     ctx->worker->add_socket(
                        ctx->proxy_socket,
                        [ctx]() { handle_proxy_read(ctx); },
                        nullptr,
                        [ctx]() { close_tcp_ctx(ctx); }
                    );
                }
            });
        }
    }
    return ERR_OK;
}

// Established state handler (Worker Thread) - DOWNSTREAM ASYNC
void handle_proxy_read(TcpCtx* ctx) {
    if (ctx->closed) return;
    
    // Check flow control flag (Atomic check would be better, but bool is okay-ish here)
    if (ctx->read_paused) return;

    // HEAP ALLOCATION: Use vector directly to avoid Stack Overflow with 256KB buffer
    // Also eliminates one copy (Direct Read -> Move)
    std::vector<uint8_t> data(262144);
    int r = recv(ctx->proxy_socket, (char*)data.data(), (int)data.size(), 0);
    
    if (r > 0) {
        data.resize(r); // Resize to actual bytes read
        
        MainDispatcher::instance().queue_task([ctx, d = std::move(data)]() {
            // Running on Main Thread
            std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
            if (ctx->client_pcb && !ctx->closed) {
                // 1. If pending data exists, append all and ensure paused
                if (!ctx->downstream_pending.empty()) {
                    ctx->downstream_pending.insert(ctx->downstream_pending.end(), d.begin(), d.end());
                    if (!ctx->read_paused) {
                        ctx->read_paused = true;
                        ctx->worker->queue_task([ctx]() {\n                            if (ctx->proxy_socket != INVALID_SOCKET) {
                                ctx->worker->add_socket(ctx->proxy_socket, nullptr, nullptr, [ctx]() { close_tcp_ctx(ctx); });
                            }
                        });
                    }
                    return;
                }

                // 2. Try direct write
                size_t written = 0;
                u16_t limit = tcp_sndbuf(ctx->client_pcb);
                if (limit > 0) {
                    size_t chunk = (std::min)((size_t)limit, d.size());
                    if (chunk > 0xffff) chunk = 0xffff;
                    if (tcp_write(ctx->client_pcb, d.data(), (u16_t)chunk, 1) == ERR_OK) {
                        tcp_output(ctx->client_pcb);
                        written = chunk;
                    }
                }

                // 3. Buffer remainder if any
                if (written < d.size()) {
                    ctx->downstream_pending.insert(ctx->downstream_pending.end(), d.begin() + written, d.end());
                    
                    if (!ctx->read_paused) {
                        ctx->read_paused = true;
                        ctx->worker->queue_task([ctx]() {
                            if (ctx->proxy_socket != INVALID_SOCKET) {
                                ctx->worker->add_socket(ctx->proxy_socket, nullptr, nullptr, [ctx]() { close_tcp_ctx(ctx); });
                            }
                        });
                    }
                }
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
    char resp[1024];
    int r = recv(ctx->proxy_socket, resp, sizeof(resp) - 1, 0);
    
    if (r > 0) {
        resp[r] = 0;
        if (strstr(resp, "200") != NULL) {
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

    std::string sni = parse_tls_sni(ctx->sni_buffer.data(), ctx->sni_buffer.size());
    std::string target_host;
    
    if (!sni.empty()) {
        target_host = sni;
    } else {
        uint32_t ip = ctx->target.original_dst_ip;
        char ip_buf[32];
        sprintf_s(ip_buf, "%d.%d.%d.%d", 
            ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
        target_host = ip_buf;
    }

    char cmd[1024];
    uint16_t port = ntohs(ctx->target.original_dst_port);
    sprintf_s(cmd, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", target_host.c_str(), port, target_host.c_str(), port);
    
    int sent = send(ctx->proxy_socket, cmd, (int)strlen(cmd), 0);
    if (sent == SOCKET_ERROR) {
         if (WSAGetLastError() != WSAEWOULDBLOCK) {
             close_tcp_ctx(ctx);
             return;
         }
         close_tcp_ctx(ctx); 
         return;
    }

    ctx->state = TcpCtx::HANDSHAKE;

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
                    if (ctx->sni_buffer[0] != 0x16) ready = true; 
                    else { 
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