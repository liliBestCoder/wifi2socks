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
    
    // Sniffing
    std::vector<uint8_t> sni_buffer;
    std::vector<uint8_t> upstream_data; // Pre-connect buffer (Payload to be sent after connect) 
    std::string detected_domain;        // Stored SNI/Host result
    bool use_direct_mode;               // Fallback decision
    
    // Zero-Copy Queue
    std::deque<std::vector<uint8_t>> tx_queue;
    size_t tx_acked_offset;   // Bytes acked in tx_queue.front()
    size_t tx_written_idx;    // Current buffer index being written to LwIP
    size_t tx_written_offset; // Bytes written in tx_queue[tx_written_idx] 
    
    std::mutex data_mtx;
    Worker* worker;

    // States: 
    // PRE_CONNECT: buffering client data to sniff SNI
    // CONNECTING: socket connecting to proxy
    // HANDSHAKE: sent CONNECT, waiting for 200 OK
    // ESTABLISHED: tunnel ready
    enum State { PRE_CONNECT, CONNECTING, HANDSHAKE, ESTABLISHED } state;

    TcpCtx() : client_pcb(NULL), proxy_socket(INVALID_SOCKET), closed(false), connected(false), read_paused(false), worker(NULL), state(PRE_CONNECT),
               tx_acked_offset(0), tx_written_idx(0), tx_written_offset(0), use_direct_mode(false) {
        sni_buffer.reserve(MAX_SNI_LEN);
        upstream_data.reserve(8192); 
    }
};

void close_tcp_ctx(TcpCtx* ctx);
void handle_proxy_read(TcpCtx* ctx);
void connect_to_proxy_async(TcpCtx* ctx);

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
        MainDispatcher::instance().queue_task([ctx]() {
            final_cleanup_on_main(ctx);
        });
    }
}

// Internal helper: Try to write pending buffers to LwIP (Copy Mode)
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

        // Zero-Copy: Pass 0 as copy flag. 
        // std::deque references are stable upon push_back, so this is safe as long as we don't pop until ACK.
        err_t err = tcp_write(ctx->client_pcb, 
                              buf.data() + ctx->tx_written_offset, 
                              chunk, 
                              0); // 0 = TCP_WRITE_FLAG_COPY (No Copy)
                              
        if (err == ERR_OK) {
            // printf("[LwIP] Wrote %d bytes to client.\n", chunk); // Debug log
            ctx->tx_written_offset += chunk;
            if (ctx->tx_written_offset >= buf.size()) {
                ctx->tx_written_idx++;
                ctx->tx_written_offset = 0;
            }
            tcp_output(ctx->client_pcb);
        } else if (err == ERR_MEM) {
            // Debug log for memory pressure
            printf("[LwIP] tcp_write ERR_MEM. Waiting for ACK.\n");
            break;
        } else {
            printf("[LwIP] tcp_write failed: %d. Closing.\n", err);
            close_tcp_ctx(ctx);
            return;
        }
    }
}

// Flow Control Callback (Main Thread)
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

// Established state handler (Worker Thread) - DOWNSTREAM ASYNC
void handle_proxy_read(TcpCtx* ctx) {
    if (ctx->closed) return;
    
    // Optimization: Use thread_local buffer to avoid allocation/zero-fill overhead per read
    thread_local std::vector<uint8_t> read_buf(262144);
    
    int r = recv(ctx->proxy_socket, (char*)read_buf.data(), (int)read_buf.size(), 0);
    
    if (r > 0) {
        printf("[TCP] Recv %d bytes from Proxy. Forwarding to Client...\n", r); // LOG ENABLED
        
        // Copy only actual data
        std::vector<uint8_t> data(read_buf.begin(), read_buf.begin() + r);
        
        // Use mutable to allow moving 'd' into tx_queue
        MainDispatcher::instance().queue_task([ctx, d = std::move(data)]() mutable {
            // Running on Main Thread
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
            printf("[TCP] Proxy read error: %d\n", WSAGetLastError());
            close_tcp_ctx(ctx);
        }
    }
}

// Wait for HTTP 200 OK (Proxy Mode)
void handle_handshake_read(TcpCtx* ctx) {
    if (ctx->closed) return;
    char buf[4096]; // Increased buffer size to capture potential ServerHello
    int r = recv(ctx->proxy_socket, buf, sizeof(buf), 0);
    
    if (r > 0) {
        // Check for double CRLF to separate Header and Body
        std::string s(buf, r);
        size_t header_end = s.find("\r\n\r\n");
        
        if (header_end != std::string::npos) {
            // Check for "200" in the header part
            std::string header = s.substr(0, header_end);
            if (header.find("200") != std::string::npos) {
                printf("[TCP-Handshake] Tunnel Established (200 OK).\n");
                
                {
                    std::lock_guard<std::mutex> lock(ctx->data_mtx);
                    // 1. Flush upstream data (ClientHello) to Proxy
                    if (!ctx->upstream_data.empty()) {
                         const char* ptr = (const char*)ctx->upstream_data.data();
                         int remaining = (int)ctx->upstream_data.size();
                         int total_sent = 0;
                         while (remaining > 0) {
                             int sent = send(ctx->proxy_socket, ptr, remaining, 0);
                             if (sent == SOCKET_ERROR) {
                                 if (WSAGetLastError() == WSAEWOULDBLOCK) {
                                     Sleep(1); 
                                     continue; 
                                 } else {
                                     printf("[TCP] Flush upstream failed: %d\n", WSAGetLastError());
                                     close_tcp_ctx(ctx);
                                     return;
                                 }
                             }
                             ptr += sent;
                             remaining -= sent;
                             total_sent += sent;
                         }
                         printf("[TCP] Flushed %d bytes of client hello\n", total_sent); // LOG ENABLED
                         ctx->upstream_data.clear();
                    }
                    ctx->connected = true;
                    ctx->state = TcpCtx::ESTABLISHED;
                }

                // 2. Handle Extra Payload (Server Hello?) arriving with 200 OK
                // This is rare but possible if proxy buffers
                size_t payload_start = header_end + 4; // Skip \r\n\r\n
                if (payload_start < (size_t)r) {
                    size_t payload_len = (size_t)r - payload_start;
                    printf("[TCP] Found %d bytes of payload (ServerHello?) with 200 OK. Forwarding...\n", (int)payload_len);
                    
                    std::vector<uint8_t> extra_data((uint8_t*)(buf + payload_start), (uint8_t*)(buf + r));
                    
                    // Push to LwIP
                    MainDispatcher::instance().queue_task([ctx, d = std::move(extra_data)]() mutable {
                        std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
                        if (ctx->client_pcb && !ctx->closed) {
                            ctx->tx_queue.push_back(std::move(d));
                            try_send_downstream(ctx);
                        }
                    });
                }
                
                // 3. Switch to standard read handler
                ctx->worker->add_socket(
                    ctx->proxy_socket,
                    [ctx]() { handle_proxy_read(ctx); },
                    nullptr,
                    [ctx]() { close_tcp_ctx(ctx); }
                );
            } else {
                printf("[TCP] Handshake Rejected. Header: %s\n", header.c_str());
                close_tcp_ctx(ctx);
            }
        } else { 
            // Header incomplete? Wait for more? 
            // For simple proxy implementation, we assume header fits in one packet.
            // If not, we might need a buffer. But usually it fits.
            printf("[TCP] Incomplete HTTP Header received. Closing.\n");
            close_tcp_ctx(ctx);
        }
    } else if (r == 0) {
        printf("[TCP] Proxy Closed during handshake\n");
        close_tcp_ctx(ctx);
    } else {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            printf("[TCP] Handshake Recv Error: %d\n", WSAGetLastError());
            close_tcp_ctx(ctx);
        }
    }
}

void handle_proxy_connect(TcpCtx* ctx) {
    if (ctx->closed) return;

    int err = 0; int len = sizeof(err);
    getsockopt(ctx->proxy_socket, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
    if (err != 0) {
        printf("[TCP] Connect Failed: %d\n", err);
        close_tcp_ctx(ctx);
        return;
    }

    // Try Parse SNI or Host from buffer
    std::string sni = parse_tls_sni(ctx->sni_buffer.data(), ctx->sni_buffer.size());
    std::string target_host;
    
    if (!sni.empty()) {
        target_host = sni;
        printf("[TCP] SNI Found: %s\n", sni.c_str());
    } else {
        target_host = parse_http_host(ctx->sni_buffer.data(), ctx->sni_buffer.size());
        if (!target_host.empty()) {
            printf("[TCP] HTTP Host Found: %s\n", target_host.c_str());
        }
    }

    char cmd[1024];
    uint16_t port = ntohs(ctx->target.original_dst_port);

    if (!target_host.empty()) {
        // Case 1: Use Domain Name
        sprintf_s(cmd, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", target_host.c_str(), port, target_host.c_str(), port);
    } else {
        // Case 2: No SNI. Check FakeIP or use Real IP.
        uint32_t ip = ctx->target.original_dst_ip;
        char ip_buf[32];
        sprintf_s(ip_buf, "%d.%d.%d.%d", 
            ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
            
        // Check if it is a Fake IP, try to recover domain
        if (FakeIpMapper::instance().is_fake_ip(ip)) {
            std::string mapped_domain = FakeIpMapper::instance().get_domain(ip);
            if (!mapped_domain.empty()) {
                printf("[TCP] Recovered Domain from FakeIP: %s -> %s\n", ip_buf, mapped_domain.c_str());
                sprintf_s(cmd, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", mapped_domain.c_str(), port, mapped_domain.c_str(), port);
            } else {
                // FakeIP but lost mapping? Fallback to IP (will likely fail on proxy but we must try)
                sprintf_s(cmd, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", ip_buf, port, ip_buf, port);
            }
        } else {
            // Real IP (e.g. 106.13.x.x)
            // CORRECT LOGIC: Send CONNECT IP:PORT to proxy. Let Proxy handle it.
            printf("[TCP] No SNI/Host. Connecting to IP via Proxy: %s:%d\n", ip_buf, port);
            sprintf_s(cmd, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", ip_buf, port, ip_buf, port);
        }
    }
    
    int sent = send(ctx->proxy_socket, cmd, (int)strlen(cmd), 0);
    if (sent == SOCKET_ERROR) {
         if (WSAGetLastError() != WSAEWOULDBLOCK) {
             printf("[TCP] Failed to send CONNECT header: %d\n", WSAGetLastError());
             close_tcp_ctx(ctx);
             return;
         }
         // EWOULDBLOCK on CONNECT packet? Extremely rare for start of connection, but...
         // We might need to handle this if it happens. For now, assume it works or fails.
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
        if (ctx->proxy_socket == INVALID_SOCKET) { close_tcp_ctx(ctx); return; }
        u_long mode = 1; ioctlsocket(ctx->proxy_socket, FIONBIO, &mode);

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
        } else { addr.sin_addr.S_addr = 0x0100007F; } // Default to 127.0.0.1
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PROXY_PORT); // Ensure app_config.h PROXY_PORT is correct (2080)

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
        
        if (ctx->state == TcpCtx::PRE_CONNECT) {
            bool ready = false;
            // Sniff
            std::string sni = parse_tls_sni(ctx->sni_buffer.data(), ctx->sni_buffer.size());
            if (!sni.empty()) {
                ctx->detected_domain = sni;
                ready = true;
            } else {
                std::string host = parse_http_host(ctx->sni_buffer.data(), ctx->sni_buffer.size());
                if (!host.empty()) {
                    ctx->detected_domain = host;
                    ready = true;
                }
            }

            // Check if buffer is full or non-protocol
            if (!ready) {
                if (ctx->sni_buffer.size() >= MAX_SNI_LEN || (ctx->sni_buffer.size() > 64 && ctx->sni_buffer[0] != 0x16 && !is_http_start(ctx->sni_buffer.data(), ctx->sni_buffer.size()))) {
                    ready = true; // Give up
                }
            }
            
            if (ready) {
                // Always use Proxy (HTTP CONNECT)
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
    tcp_arg(newpcb, ctx);
    tcp_recv(newpcb, tcp_client_recv);
    tcp_sent(newpcb, tcp_client_sent);
    tcp_err(newpcb, [](void* arg, err_t err) { 
        TcpCtx* c = (TcpCtx*)arg;
        c->client_pcb = NULL; 
        close_tcp_ctx(c); 
    });
    // Wait for data
    return ERR_OK;
}