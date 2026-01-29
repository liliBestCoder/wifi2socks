#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX
// Ensure FD_SETSIZE is defined before winsock
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#include <iostream>
#include <vector>
#include <map>
#include <mutex>
#include <ctime>
#include <stdarg.h>
#include <atomic>
#include <thread>

#include "worker.h"

#pragma comment(lib, "Ws2_32.lib")

// --- CONFLICT RESOLUTION ---
#define timeval     lwip_timeval
#define fd_set      lwip_fd_set
#define in_addr     lwip_in_addr
#define sockaddr    lwip_sockaddr
#define sockaddr_in lwip_sockaddr_in
#define sockaddr_storage lwip_sockaddr_storage
#define linger      lwip_linger

#define htonl       lwip_htonl
#define ntohl       lwip_ntohl
#define htons       lwip_htons
#define ntohs       lwip_ntohs
#define inet_addr   lwip_inet_addr
#define inet_ntoa   lwip_inet_ntoa

#ifdef s_addr
#undef s_addr
#endif

extern "C" {
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/ip.h"
#include "lwip/timeouts.h"
#include "netif/etharp.h"
#include "lwip/inet_chksum.h"
err_t ethernet_input(struct pbuf *p, struct netif *netif);
}

#undef timeval
#undef fd_set
#undef in_addr
#undef sockaddr
#undef sockaddr_in
#undef sockaddr_storage
#undef linger
#undef htonl
#undef ntohl
#undef htons
#undef ntohs
#undef inet_addr
#undef inet_ntoa

// --- Configuration ---
#define TAP_IP          "10.0.0.1"
#define TAP_NETMASK     "255.255.255.0"
#define TAP_GW          "10.0.0.1" 
#define PROXY_IP        "192.168.11.250"
#define PROXY_PORT      2080
#define LWIP_LISTEN_PORT 7000
#define MAX_SNI_LEN     2048

#define TAP_CONTROL_CODE(request, method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)

#define TAP_WIN_PATH "\\\\.\\%s.tap"

// --- Headers ---
#pragma pack(push, 1)
struct EthHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};
struct ArpPacket {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
};
#pragma pack(pop)

// --- Globals ---
HANDLE g_tap = INVALID_HANDLE_VALUE;
struct netif g_netif;
uint8_t TAP_MAC[6] = { 0x00, 0xFF, 0x92, 0xEA, 0x69, 0x5C }; 
uint8_t HOST_MAC[6] = { 0 }; 
std::atomic<bool> g_host_mac_known(false);

struct NatEntry {
    uint32_t original_dst_ip;
    uint16_t original_dst_port;
    uint64_t last_active;
};
std::map<uint16_t, NatEntry> g_nat_table;
std::mutex g_nat_mtx;

std::recursive_mutex g_lwip_mtx; // Global LwIP lock

// --- Forward Declarations ---
void tap_send_async(const uint8_t* buf, int len);

// --- Logging ---
void log_debug(const char* format, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    OutputDebugStringA(buf);
}

uint32_t get_now_ms() { return (uint32_t)GetTickCount64(); }
extern "C" u32_t sys_now() { return get_now_ms(); }
extern "C" unsigned int sys_win_rand() { return (unsigned int)rand(); }
extern "C" void lwip_win32_platform_diag(const char *format, ...) {
    va_list ap; va_start(ap, format); 
    char buf[1024]; vsnprintf(buf, sizeof(buf), format, ap);
    OutputDebugStringA(buf); va_end(ap);
}

// --- Checksum Helpers ---
uint16_t ip_chksum_simple(void* dataptr, int len) {
    uint32_t acc = 0;
    uint16_t* ptr = (uint16_t*)dataptr;
    while (len > 1) { acc += *ptr++; len -= 2; }
    if (len == 1) acc += *(uint8_t*)ptr;
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)~(acc);
}

uint32_t calculate_raw_sum(const void* data, int len) {
    uint32_t sum = 0;
    const uint16_t* ptr = (const uint16_t*)data;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len > 0) { sum += (uint16_t)(*(const uint8_t*)ptr << 8); }
    return sum;
}

void recalculate_tcp_checksum(struct ip_hdr* ip, uint8_t* tcp_base, int tcp_len) {
    *(uint16_t*)(tcp_base + 16) = 0;
    uint32_t sum = 0;
    uint16_t* ip_src = (uint16_t*)&ip->src.addr;
    sum += ip_src[0]; sum += ip_src[1];
    uint16_t* ip_dst = (uint16_t*)&ip->dest.addr;
    sum += ip_dst[0]; sum += ip_dst[1];
    sum += ::htons(IP_PROTO_TCP);
    sum += ::htons((uint16_t)tcp_len);
    sum += calculate_raw_sum(tcp_base, tcp_len);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    *(uint16_t*)(tcp_base + 16) = (uint16_t)~sum;
}

// --- TAP Write ---
std::mutex g_write_mtx;
void tap_send_async(const uint8_t* buf, int len) {
    if (len <= 0) return; 
    std::lock_guard<std::mutex> lk(g_write_mtx);
    OVERLAPPED ol = {0};
    ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ol.hEvent) return;
    DWORD written = 0;
    if (!WriteFile(g_tap, buf, len, &written, &ol)) {
        if (GetLastError() == ERROR_IO_PENDING) {
            WaitForSingleObject(ol.hEvent, 1000); 
        }
    }
    CloseHandle(ol.hEvent);
}

err_t tap_linkoutput(struct netif* netif, struct pbuf* p) {
    std::vector<uint8_t> buf;
    buf.reserve(p->tot_len);
    for (struct pbuf* q = p; q != NULL; q = q->next) {
        buf.insert(buf.end(), (uint8_t*)q->payload, (uint8_t*)q->payload + q->len);
    }

    if (buf.size() > 34) {
        struct ip_hdr* ip = (struct ip_hdr*)(buf.data() + 14);
        if (IPH_V(ip) == 4 && IPH_PROTO(ip) == IP_PROTO_TCP) {
             if (ip->src.addr == ::inet_addr(TAP_GW)) {
                 uint8_t* tcp_base = buf.data() + 14 + IPH_HL(ip) * 4;
                 uint16_t src_port = *(uint16_t*)tcp_base;
                 uint16_t dst_port = *(uint16_t*)(tcp_base + 2);
                 
                 if (src_port == ::htons(LWIP_LISTEN_PORT)) {
                     NatEntry target = { 0 };
                     {
                         std::lock_guard<std::mutex> lk(g_nat_mtx);
                         auto it = g_nat_table.find(::ntohs(dst_port));
                         if (it != g_nat_table.end()) target = it->second;
                     }
                     
                     if (target.original_dst_ip != 0) {
                         ip->src.addr = target.original_dst_ip;
                         *(uint16_t*)tcp_base = target.original_dst_port;
                         
                         IPH_CHKSUM_SET(ip, 0);
                         IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
                         
                         uint16_t ip_len = ::ntohs(*(uint16_t*)((uint8_t*)ip + 2));
                         int tcp_len = ip_len - IPH_HL(ip) * 4;
                         recalculate_tcp_checksum(ip, tcp_base, tcp_len);
                     }
                 }
             }
        }
    }

    tap_send_async(buf.data(), (int)buf.size());
    return ERR_OK;
}

std::string parse_tls_sni(const uint8_t* data, size_t len) {
    if (len < 5 || data[0] != 0x16) return ""; 
    size_t pos = 5;
    if (pos + 4 > len) return "";
    if (data[pos] != 0x01) return ""; 
    pos += 4; 
    if (pos + 2 > len) return "";
    pos += 2; 
    pos += 32; 
    if (pos + 1 > len) return "";
    uint8_t session_id_len = data[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > len) return "";
    uint16_t cipher_suite_len = (data[pos] << 8) | data[pos+1];
    pos += 2 + cipher_suite_len;
    if (pos + 1 > len) return "";
    uint8_t comp_method_len = data[pos];
    pos += 1 + comp_method_len;
    if (pos + 2 > len) return "";
    uint16_t ext_len = (data[pos] << 8) | data[pos+1];
    pos += 2;
    size_t ext_end = pos + ext_len;
    if (ext_end > len) ext_end = len;
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos+1];
        uint16_t ext_data_len = (data[pos+2] << 8) | data[pos+3];
        pos += 4;
        if (ext_type == 0x0000) { 
            if (pos + 5 > ext_end) return "";
            pos += 2; 
            uint8_t name_type = data[pos]; 
            uint16_t name_len = (data[pos+1] << 8) | data[pos+2];
            pos += 3;
            if (name_type == 0 && pos + name_len <= ext_end) {
                return std::string((const char*)(data + pos), name_len);
            }
        }
        pos += ext_data_len;
    }
    return "";
}

// --- TCP Logic with Worker Pool ---
struct TcpCtx {
    struct tcp_pcb* client_pcb;
    SOCKET proxy_socket;
    std::atomic<bool> closed;
    std::atomic<bool> connected;
    NatEntry target;
    std::vector<uint8_t> sni_buffer;
    std::vector<uint8_t> upstream_data; // Pre-connect buffer
    std::mutex data_mtx;
    Worker* worker;

    enum State { PRE_CONNECT, CONNECTING, HANDSHAKE, ESTABLISHED } state;

    TcpCtx() : client_pcb(NULL), proxy_socket(INVALID_SOCKET), closed(false), connected(false), worker(NULL), state(PRE_CONNECT) {
        sni_buffer.reserve(MAX_SNI_LEN);
        upstream_data.reserve(4096);
    }
};

void close_tcp_ctx(TcpCtx* ctx) {
    if (!ctx || ctx->closed.exchange(true)) return;

    if (ctx->worker && ctx->proxy_socket != INVALID_SOCKET) {
        // Stop monitoring immediately (queued)
        // We do NOT call remove_socket here because we need to sequence it with the deletion below.
    }

    std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
    if (ctx->client_pcb) {
        tcp_arg(ctx->client_pcb, NULL);
        tcp_recv(ctx->client_pcb, NULL);
        tcp_err(ctx->client_pcb, NULL);
        tcp_close(ctx->client_pcb);
        ctx->client_pcb = NULL;
    }
    
    // Note: We don't close proxy_socket here anymore if worker is active, 
    // because it might have been created in worker and we need to close it there to avoid races.

    if (ctx->worker) {
        ctx->worker->queue_task([ctx]() {
            if (ctx->proxy_socket != INVALID_SOCKET) {
                // Remove from map, THEN close and delete
                ctx->worker->remove_socket(ctx->proxy_socket, [ctx, s = ctx->proxy_socket]() {
                    closesocket(s);
                    delete ctx;
                });
            } else {
                delete ctx;
            }
        });
    } else {
        if (ctx->proxy_socket != INVALID_SOCKET) closesocket(ctx->proxy_socket);
        delete ctx;
    }
}

// Forward declarations for callbacks
void handle_handshake_read(TcpCtx* ctx);
void handle_proxy_read(TcpCtx* ctx);
void handle_proxy_connect(TcpCtx* ctx);

// 3. Established state handler (Transparent Proxy)
void handle_proxy_read(TcpCtx* ctx) {
    if (ctx->closed) return;
    char buf[16384];
    int r = recv(ctx->proxy_socket, buf, sizeof(buf), 0);
    if (r > 0) {
        std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
        if (ctx->client_pcb && !ctx->closed) {
            tcp_write(ctx->client_pcb, buf, (u16_t)r, 1);
            tcp_output(ctx->client_pcb);
        }
    }
    else {
        // Error or Close
        close_tcp_ctx(ctx);
    }
}

// 2. Handshake response handler (Waiting for HTTP 200)
void handle_handshake_read(TcpCtx* ctx) {
    if (ctx->closed) return;
    char resp[1024];
    int r = recv(ctx->proxy_socket, resp, sizeof(resp) - 1, 0);
    
    if (r > 0) {
        resp[r] = 0;
        // Simple check for 200 OK. 
        // Real implementation should parse HTTP properly, but this suffices for typical proxies.
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
            
            // Switch to Transparent Proxy Mode
            ctx->worker->add_socket(
                ctx->proxy_socket,
                [ctx]() { handle_proxy_read(ctx); }, // on_read
                nullptr, // on_write (disable)
                [ctx]() { close_tcp_ctx(ctx); }
            );
        } else {
            // Proxy error
            close_tcp_ctx(ctx);
        }
    } else {
        // Error or Close during handshake
        close_tcp_ctx(ctx);
    }
}

// 1. Connect completion handler
void handle_proxy_connect(TcpCtx* ctx) {
    if (ctx->closed) return;

    // Check connection result
    int err = 0; int len = sizeof(err);
    if (getsockopt(ctx->proxy_socket, SOL_SOCKET, SO_ERROR, (char*)&err, &len) == SOCKET_ERROR) {
        err = WSAGetLastError();
    }
    
    if (err != 0) {
        close_tcp_ctx(ctx);
        return;
    }

    // Connected. Send CONNECT command.
    std::string sni = parse_tls_sni(ctx->sni_buffer.data(), ctx->sni_buffer.size());
    std::string target_host;
    if (!sni.empty()) target_host = sni;
    else {
        char ip_str[64]; struct in_addr ia; ia.S_un.S_addr = ctx->target.original_dst_ip;
        strcpy_s(ip_str, ::inet_ntoa(ia)); target_host = ip_str;
    }

    char cmd[1024];
    uint16_t port = ntohs(ctx->target.original_dst_port);
    sprintf_s(cmd, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", target_host.c_str(), port, target_host.c_str(), port);
    
    // We assume socket buffer is empty enough for this small command. 
    // In strict non-blocking, we should handle partial sends, but for < 1k command on fresh socket, it's fine.
    int sent = send(ctx->proxy_socket, cmd, (int)strlen(cmd), 0);
    if (sent == SOCKET_ERROR) {
         if (WSAGetLastError() != WSAEWOULDBLOCK) {
             close_tcp_ctx(ctx);
             return;
         }
         // If WOULDBLOCK (extremely rare for fresh socket), we should actually keep on_write and retry.
         // For simplification, we fail here.
         close_tcp_ctx(ctx); 
         return;
    }

    ctx->state = TcpCtx::HANDSHAKE;

    // Switch to Read Interest (Waiting for 200 OK)
    // Remove on_write, Add on_read
    ctx->worker->add_socket(
        ctx->proxy_socket,
        [ctx]() { handle_handshake_read(ctx); }, // on_read
        nullptr, // on_write (disable)
        [ctx]() { close_tcp_ctx(ctx); }
    );
}

// Helper to initiate async connection
void connect_to_proxy_async(TcpCtx* ctx) {
    // 1. Create Socket
    ctx->proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->proxy_socket == INVALID_SOCKET) {
        close_tcp_ctx(ctx);
        return;
    }

    // 2. Set Non-Blocking
    u_long mode = 1;
    if (ioctlsocket(ctx->proxy_socket, FIONBIO, &mode) != 0) {
        close_tcp_ctx(ctx);
        return;
    }

    // 3. Assign Worker
    ctx->worker = WorkerPool::instance().get_worker(ctx->target.original_dst_port);
    if (!ctx->worker) ctx->worker = WorkerPool::instance().get_next_worker();

    // 4. Start Connect
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.S_un.S_addr = inet_addr(PROXY_IP);
    addr.sin_port = htons(PROXY_PORT);

    int r = connect(ctx->proxy_socket, (sockaddr*)&addr, sizeof(addr));
    
    if (r == 0) {
        // Connected immediately (local proxy?)
        // Queue the logic to run in worker thread to maintain consistency
        ctx->state = TcpCtx::CONNECTING;
        ctx->worker->add_socket(
            ctx->proxy_socket,
            nullptr, // no read yet
            [ctx]() { handle_proxy_connect(ctx); }, // Trigger connect handler (it handles sending CONNECT)
            [ctx]() { close_tcp_ctx(ctx); }
        );
    } else {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            // Pending
            ctx->state = TcpCtx::CONNECTING;
            ctx->worker->add_socket(
                ctx->proxy_socket,
                nullptr, // no read yet
                [ctx]() { handle_proxy_connect(ctx); }, // Wake up when writable (connected)
                [ctx]() { close_tcp_ctx(ctx); }
            );
        } else {
            // Failed
            close_tcp_ctx(ctx);
        }
    }
}

err_t tcp_client_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    TcpCtx* ctx = (TcpCtx*)arg;
    if (!p) { close_tcp_ctx(ctx); return ERR_OK; }
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
        if (ctx->connected) {
             // Race condition fallback
            send(ctx->proxy_socket, (const char*)p->payload, p->len, 0);
        } else {
            uint8_t* d = (uint8_t*)p->payload;
            ctx->upstream_data.insert(ctx->upstream_data.end(), d, d + p->len);
            
            if (ctx->proxy_socket == INVALID_SOCKET) {
                if (ctx->sni_buffer.size() < MAX_SNI_LEN) {
                    size_t to_copy = (std::min)((size_t)p->len, (size_t)(MAX_SNI_LEN - ctx->sni_buffer.size()));
                    ctx->sni_buffer.insert(ctx->sni_buffer.end(), d, d + to_copy);
                }
                
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
                    // Start Async Connect
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
    NatEntry target = { 0 };
    {
        std::lock_guard<std::mutex> lk(g_nat_mtx);
        auto it = g_nat_table.find(client_port);
        if (it != g_nat_table.end()) target = it->second;
    }
    if (target.original_dst_ip == 0) return ERR_ABRT;
    
    tcp_nagle_disable(newpcb);
    TcpCtx* ctx = new TcpCtx();
    ctx->client_pcb = newpcb;
    ctx->target = target;
    tcp_arg(newpcb, ctx);
    tcp_recv(newpcb, tcp_client_recv);
    
    tcp_err(newpcb, [](void* arg, err_t err) { 
        TcpCtx* c = (TcpCtx*)arg;
        c->client_pcb = NULL; 
        close_tcp_ctx(c); 
    });
    return ERR_OK;
}

// --- UDP Session with Worker Pool ---
struct UdpKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    bool operator<(const UdpKey& o) const { return memcmp(this, &o, sizeof(UdpKey)) < 0; }
};

struct UdpSession {
    SOCKET sock;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    std::atomic<uint64_t> last_active;
    std::atomic<bool> closed;
    Worker* worker;
    UdpSession() : sock(INVALID_SOCKET), closed(false), worker(NULL) { last_active = get_now_ms(); }
};

std::map<UdpKey, UdpSession*> g_udp_sessions;
std::mutex g_udp_mtx;

void handle_udp_read(UdpSession* sess) {
    if (sess->closed) return;
    char buf[2048];
    sockaddr_in from;
    int from_len = sizeof(from);
    int r = recvfrom(sess->sock, buf, sizeof(buf), 0, (sockaddr*)&from, &from_len);
    
    if (r > 0 && g_host_mac_known) {
        sess->last_active = get_now_ms();
        // Construct Reply
        uint8_t frame[2048];
        if (14 + 20 + 8 + r > 2048) return;

        memcpy(frame, HOST_MAC, 6);
        memcpy(frame + 6, TAP_MAC, 6);
        *(uint16_t*)(frame + 12) = htons(0x0800);

        uint8_t* ip = frame + 14;
        uint8_t* udp_hdr = ip + 20;
        
        // IPv4 Header
        memset(ip, 0, 20);
        ip[0] = 0x45; ip[9] = 17; ip[8] = 64;
        *(uint16_t*)(ip + 2) = htons((uint16_t)(20 + 8 + r));
        *(uint32_t*)(ip + 12) = sess->dst_ip;
        *(uint32_t*)(ip + 16) = sess->src_ip;
        *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

        // UDP Header
        *(uint16_t*)(udp_hdr + 0) = sess->dst_port;
        *(uint16_t*)(udp_hdr + 2) = sess->src_port;
        *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + r));
        *(uint16_t*)(udp_hdr + 6) = 0;
        memcpy(udp_hdr + 8, buf, r);

        tap_send_async(frame, 14 + 20 + 8 + r);
    } else if (r == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
             // Close handled by timeout
        }
    }
}

// Close helper
void close_udp_session(UdpSession* sess) {
    if (sess->closed.exchange(true)) return;
    if (sess->worker) sess->worker->remove_socket(sess->sock);
    if (sess->sock != INVALID_SOCKET) closesocket(sess->sock);
    
    // Remove from map
    {
        std::lock_guard<std::mutex> lk(g_udp_mtx);
        UdpKey key = { sess->src_ip, sess->dst_ip, sess->src_port, sess->dst_port };
        g_udp_sessions.erase(key);
    }
    delete sess;
}

// --- Main Processing ---
void process_tap_frame(uint8_t* buf, int len) {
    if (len < 14) return;

    if (!g_host_mac_known) {
        memcpy(HOST_MAC, buf + 6, 6);
        g_host_mac_known = true;
    }

    uint16_t eth_type = ::ntohs(*(uint16_t*)(buf + 12));
    if (eth_type == 0x0806) {
        struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        if (p) {
            pbuf_take(p, buf, len);
            g_netif.input(p, &g_netif);
        }
        return; 
    }

    struct ip_hdr* ip = (struct ip_hdr*)(buf + 14);
    if (IPH_V(ip) == 4) {
        if (IPH_PROTO(ip) == IP_PROTO_UDP) {
            uint8_t* udp_ptr = buf + 14 + IPH_HL(ip) * 4;
            uint16_t src_port = *(uint16_t*)(udp_ptr + 0);
            uint16_t dst_port = *(uint16_t*)(udp_ptr + 2);
            uint8_t* payload = udp_ptr + 8;
            int pay_len = len - (14 + IPH_HL(ip) * 4 + 8);

            if (pay_len >= 0) {
                UdpKey key = { ip->src.addr, ip->dest.addr, src_port, dst_port };
                UdpSession* sess = NULL;
                {
                    std::lock_guard<std::mutex> lk(g_udp_mtx);
                    auto it = g_udp_sessions.find(key);
                    if (it != g_udp_sessions.end()) sess = it->second;
                }

                if (!sess) {
                    sess = new UdpSession();
                    sess->src_ip = ip->src.addr; sess->dst_ip = ip->dest.addr;
                    sess->src_port = src_port; sess->dst_port = dst_port;
                    sess->sock = socket(AF_INET, SOCK_DGRAM, 0);
                    
                    if (sess->sock != INVALID_SOCKET) {
                        u_long mode = 1;
                        ioctlsocket(sess->sock, FIONBIO, &mode);
                        
                        sess->worker = WorkerPool::instance().get_worker(src_port ^ dst_port);
                        if (!sess->worker) sess->worker = WorkerPool::instance().get_next_worker();

                        {
                            std::lock_guard<std::mutex> lk(g_udp_mtx);
                            g_udp_sessions[key] = sess;
                        }
                        
                        sess->worker->add_socket(
                            sess->sock,
                            [sess]() { handle_udp_read(sess); },
                            nullptr,
                            [sess]() { close_udp_session(sess); }
                        );

                    } else {
                        delete sess; sess = NULL;
                    }
                }

                if (sess) {
                    sess->last_active = get_now_ms();
                    sockaddr_in dest;
                    dest.sin_family = AF_INET;
                    dest.sin_addr.S_un.S_addr = sess->dst_ip;
                    dest.sin_port = sess->dst_port;
                    sendto(sess->sock, (const char*)payload, pay_len, 0, (sockaddr*)&dest, sizeof(dest));
                }
            }
            return; 
        }

        if (IPH_PROTO(ip) == IP_PROTO_TCP) {
            uint8_t* tcp_base = buf + 14 + IPH_HL(ip) * 4;
            uint16_t src_port = *(uint16_t*)(tcp_base); 
            uint16_t dst_port = *(uint16_t*)(tcp_base + 2);
            uint32_t dst_ip = ip->dest.addr;

            {
                std::lock_guard<std::mutex> lk(g_nat_mtx);
                NatEntry& e = g_nat_table[::ntohs(src_port)]; 
                e.original_dst_ip = dst_ip;
                e.original_dst_port = dst_port; 
                e.last_active = get_now_ms();
            }

            ip->dest.addr = ::inet_addr(TAP_GW);
            *(uint16_t*)(tcp_base + 2) = ::htons(LWIP_LISTEN_PORT);

            IPH_CHKSUM_SET(ip, 0);
            IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
            
            uint16_t ip_len = ::ntohs(*(uint16_t*)((uint8_t*)ip + 2));
            int tcp_len = ip_len - IPH_HL(ip) * 4;
            if (tcp_len > 0) {
                recalculate_tcp_checksum(ip, tcp_base, tcp_len);
            }
        }

        struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        if (p) {
            pbuf_take(p, buf, len);
            if (g_netif.input(p, &g_netif) != ERR_OK) {
                pbuf_free(p);
            }
        }
    }
}

err_t netif_init_cb(struct netif* netif) {
    netif->linkoutput = tap_linkoutput;
    netif->output = etharp_output;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;
    netif->hwaddr_len = 6;
    memcpy(netif->hwaddr, TAP_MAC, 6);
    return ERR_OK;
}

int main() {
    char devicePath[256];
    sprintf_s(devicePath, sizeof(devicePath), TAP_WIN_PATH, "{92EA695C-EDAD-44C4-9950-3F306CBE9A7D}");
    log_debug("Opening TAP device: %s\n", devicePath);

    g_tap = CreateFileA(devicePath, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0); 
    
    if (g_tap == INVALID_HANDLE_VALUE) { 
        log_debug("Error opening TAP. Code=%lu\n", GetLastError()); 
        return 1; 
    }

    ULONG status = TRUE; DWORD len;
    DeviceIoControl(g_tap, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL);

    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

    // --- Init Worker Pool ---
    WorkerPool::instance().init(std::thread::hardware_concurrency());
    log_debug("Worker Pool Initialized with %d threads.\n", std::thread::hardware_concurrency());

    lwip_init();

    ip4_addr_t ip, mask, gw;
    ip4addr_aton(TAP_IP, &ip);
    ip4addr_aton(TAP_NETMASK, &mask);
    ip4addr_aton(TAP_GW, &gw);

    netif_add(&g_netif, &ip, &mask, &gw, NULL, netif_init_cb, ethernet_input);
    netif_set_default(&g_netif);
    netif_set_up(&g_netif);

    struct tcp_pcb* pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, LWIP_LISTEN_PORT);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, tcp_proxy_accept);

    log_debug("LwIP Tun2Socks Running. HTTP Proxy: %s:%d\n", PROXY_IP, PROXY_PORT);

    uint8_t buffer[65536];
    OVERLAPPED ol = {0};
    ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    DWORD bytesRead = 0;
    bool pending = false;
    uint32_t last_cleanup = get_now_ms();

    while (true) {
        if (!pending) {
            if (!ReadFile(g_tap, buffer, sizeof(buffer), &bytesRead, &ol)) {
                if (GetLastError() != ERROR_IO_PENDING) {
                    log_debug("TAP Read Error: %d\n", GetLastError());
                    break;
                }
                pending = true;
            } else {
                {
                    std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
                    process_tap_frame(buffer, bytesRead);
                }
                pending = false; 
                ol.Offset = 0; ol.OffsetHigh = 0; 
            }
        }

        if (pending) {
            DWORD waitRes = WaitForSingleObject(ol.hEvent, 2); 
            if (waitRes == WAIT_OBJECT_0) {
                if (GetOverlappedResult(g_tap, &ol, &bytesRead, FALSE)) {
                    std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
                    process_tap_frame(buffer, bytesRead);
                }
                pending = false;
                ResetEvent(ol.hEvent);
                ol.Offset = 0; ol.OffsetHigh = 0;
            }
        }

        {
            std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
            sys_check_timeouts();
        }
        
        // Clean UDP sessions
        if (get_now_ms() - last_cleanup > 5000) {
            last_cleanup = get_now_ms();
            std::vector<UdpSession*> stale_sessions;
            {
                std::lock_guard<std::mutex> lk(g_udp_mtx);
                for (auto& pair : g_udp_sessions) {
                    if (get_now_ms() - pair.second->last_active > 60000) {
                        stale_sessions.push_back(pair.second);
                    }
                }
            }
            for (auto* sess : stale_sessions) {
                close_udp_session(sess);
            }
        }
    }
    return 0;
}