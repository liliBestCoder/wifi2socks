#define _WINSOCK_DEPRECATED_NO_WARNINGS
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
#include <string>

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
#pragma pack(pop)

// --- Globals ---
HANDLE g_tap = INVALID_HANDLE_VALUE;
struct netif g_netif;
uint8_t TAP_MAC[6] = { 0x00, 0xFF, 0x92, 0xEA, 0x69, 0x5C };

// --- Logging ---
void log_debug(const char* format, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    OutputDebugStringA(buf);
    printf("%s", buf);
}

// --- Platform Helper ---
uint32_t get_now_ms() { return (uint32_t)GetTickCount64(); }
extern "C" u32_t sys_now() { return get_now_ms(); }
extern "C" unsigned int sys_win_rand() { return (unsigned int)rand(); }
extern "C" void lwip_win32_platform_diag(const char *format, ...) {
    va_list ap; va_start(ap, format); 
    char buf[1024]; vsnprintf(buf, sizeof(buf), format, ap);
    OutputDebugStringA(buf); va_end(ap);
}

// --- Checksum ---
uint16_t ip_chksum_simple(void* dataptr, int len) {
    uint32_t acc = 0;
    uint16_t* ptr = (uint16_t*)dataptr;
    while (len > 1) { acc += *ptr++; len -= 2; }
    if (len == 1) acc += *(uint8_t*)ptr;
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)~(acc);
}

// --- SNI Parser ---
// Returns extracted hostname or empty string
std::string parse_tls_sni(const uint8_t* data, size_t len) {
    if (len < 5) return "";
    
    // TLS Record Header: Type(1) Ver(2) Len(2)
    if (data[0] != 0x16) return ""; // Content Type: Handshake
    // uint16_t record_len = (data[3] << 8) | data[4];
    
    size_t pos = 5;
    if (pos + 4 > len) return "";
    
    // Handshake Header: Type(1) Len(3)
    if (data[pos] != 0x01) return ""; // Msg Type: Client Hello
    pos += 4; // Skip Handshake Header
    
    // Client Hello
    if (pos + 2 > len) return "";
    // uint16_t client_ver = (data[pos] << 8) | data[pos+1];
    pos += 2; // Skip Client Version
    
    pos += 32; // Skip Random
    
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
        
        if (ext_type == 0x0000) { // Server Name
            if (pos + 2 > ext_end) return "";
            // uint16_t list_len = (data[pos] << 8) | data[pos+1];
            pos += 2; 
            
            if (pos + 3 > ext_end) return "";
            uint8_t name_type = data[pos]; // 0x00 host_name
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

// --- Global NAT Table ---
struct NatEntry {
    uint32_t original_dst_ip;
    uint16_t original_dst_port;
    uint64_t last_active;
};
std::map<uint16_t, NatEntry> g_nat_table;
std::mutex g_nat_mtx;

// --- TCP Logic ---
enum TcpProxyState {
    TCP_STATE_NONE,
    TCP_STATE_WAIT_CLIENT_HELLO, // Buffering data from browser
    TCP_STATE_CONNECTING_PROXY,  // Connecting to 2080
    TCP_STATE_HANDSHAKE_SENT,    // Sent HTTP CONNECT
    TCP_STATE_ESTABLISHED        // Transmit
};

struct TcpCtx {
    struct tcp_pcb* client_pcb; 
    struct tcp_pcb* proxy_pcb; 
    TcpProxyState state;
    NatEntry target;
    std::vector<uint8_t> buffer; // Buffer for initial data
    
    TcpCtx() : client_pcb(NULL), proxy_pcb(NULL), state(TCP_STATE_NONE) {}
};

err_t tcp_proxy_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err);
er_t tcp_client_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err);

void tcp_close_both(TcpCtx* ctx) {
    if (!ctx) return;
    if (ctx->client_pcb) {
        tcp_arg(ctx->client_pcb, NULL);
        tcp_close(ctx->client_pcb);
        ctx->client_pcb = NULL;
    }
    if (ctx->proxy_pcb) {
        tcp_arg(ctx->proxy_pcb, NULL);
        tcp_close(ctx->proxy_pcb);
        ctx->proxy_pcb = NULL;
    }
    delete ctx;
}

err_t on_proxy_connected(void* arg, struct tcp_pcb* tpcb, err_t err) {
    TcpCtx* ctx = (TcpCtx*)arg;
    if (err != ERR_OK) {
        log_debug("[-] Proxy Connect Failed\n");
        tcp_close_both(ctx);
        return ERR_OK;
    }

    // Try to parse SNI from buffered data
    std::string sni = parse_tls_sni(ctx->buffer.data(), ctx->buffer.size());
    std::string target_host;
    
    if (!sni.empty()) {
        target_host = sni;
        log_debug("[TCP] SNI Detected: %s\n", sni.c_str());
    } else {
        // Fallback to IP
        char ip_str[64];
        struct in_addr ia;
        ia.S_un.S_addr = ctx->target.original_dst_ip;
        strcpy_s(ip_str, ::inet_ntoa(ia));
        target_host = ip_str;
        log_debug("[TCP] No SNI, using IP: %s\n", ip_str);
    }

    // Send HTTP CONNECT
    // CONNECT target:port HTTP/1.1
    // Host: target:port
    char cmd[512];
    sprintf_s(cmd, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", 
        target_host.c_str(), ::ntohs(ctx->target.original_dst_port),
        target_host.c_str(), ::ntohs(ctx->target.original_dst_port));
        
    tcp_write(tpcb, cmd, strlen(cmd), 1);
    tcp_output(tpcb);
    
    ctx->state = TCP_STATE_HANDSHAKE_SENT;
    return ERR_OK;
}

err_t tcp_proxy_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    TcpCtx* ctx = (TcpCtx*)arg;
    if (!p) { tcp_close_both(ctx); return ERR_OK; }
    
    tcp_recved(tpcb, p->tot_len);

    if (ctx->state == TCP_STATE_ESTABLISHED) {
        if (ctx->client_pcb) {
            tcp_write(ctx->client_pcb, p->payload, p->len, 1);
            tcp_output(ctx->client_pcb);
        }
    } else if (ctx->state == TCP_STATE_HANDSHAKE_SENT) {
        // Expect HTTP 200 OK
        char* data = (char*)p->payload;
        if (p->len > 12 && strncmp(data, "HTTP/1.1 200", 12) == 0) {
            // Find end of header \r\n\r\n
            uint8_t* body = NULL;
            int body_len = 0;
            
            for (int i = 0; i < p->len - 3; ++i) {
                if (data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n') {
                    body = (uint8_t*)data + i + 4;
                    body_len = p->len - (i + 4);
                    break;
                }
            }
            
            ctx->state = TCP_STATE_ESTABLISHED;
            
            if (!ctx->buffer.empty()) {
                tcp_write(tpcb, ctx->buffer.data(), ctx->buffer.size(), 1);
                ctx->buffer.clear();
            }
            
            if (body && body_len > 0 && ctx->client_pcb) {
                tcp_write(ctx->client_pcb, body, body_len, 1);
                tcp_output(ctx->client_pcb);
            }
            tcp_output(tpcb);
        } else {
            tcp_close_both(ctx);
            pbuf_free(p);
            return ERR_OK;
        }
    }
    pbuf_free(p);
    return ERR_OK;
}

er_t tcp_client_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    TcpCtx* ctx = (TcpCtx*)arg;
    if (!p) { tcp_close_both(ctx); return ERR_OK; }
    
    tcp_recved(tpcb, p->tot_len);

    if (ctx->state == TCP_STATE_ESTABLISHED) {
        if (ctx->proxy_pcb) {
            tcp_write(ctx->proxy_pcb, p->payload, p->len, 1);
            tcp_output(ctx->proxy_pcb);
        }
    } else if (ctx->state == TCP_STATE_WAIT_CLIENT_HELLO) {
        uint8_t* d = (uint8_t*)p->payload;
        ctx->buffer.insert(ctx->buffer.end(), d, d + p->len);
        
        if (ctx->buffer.size() >= 2048 || (ctx->buffer.size() > 5 && ctx->buffer[0] != 0x16)) {
            ctx->state = TCP_STATE_CONNECTING_PROXY;
            
            struct tcp_pcb* proxy_pcb = tcp_new();
            ctx->proxy_pcb = proxy_pcb;
            tcp_arg(proxy_pcb, ctx);
            tcp_recv(proxy_pcb, tcp_proxy_recv);
            
            ip_addr_t proxy_ip;
            ip4_addr_set_u32(&proxy_ip, ::inet_addr(PROXY_IP)); 
            tcp_connect(proxy_pcb, &proxy_ip, PROXY_PORT, on_proxy_connected);
        }
    } else {
        uint8_t* d = (uint8_t*)p->payload;
        ctx->buffer.insert(ctx->buffer.end(), d, d + p->len);
    }
    pbuf_free(p);
    return ERR_OK;
}

er_t tcp_accept_cb(void* arg, struct tcp_pcb* newpcb, err_t err) {
    uint16_t client_port = newpcb->remote_port;
    NatEntry target = { 0 };
    {
        std::lock_guard<std::mutex> lk(g_nat_mtx);
        auto it = g_nat_table.find(client_port);
        if (it != g_nat_table.end()) target = it->second;
    }
    if (target.original_dst_ip == 0) return ERR_ABRT;

    TcpCtx* ctx = new TcpCtx();
    ctx->client_pcb = newpcb;
    ctx->target = target;
    ctx->state = TCP_STATE_WAIT_CLIENT_HELLO; 

    tcp_arg(newpcb, ctx);
    tcp_recv(newpcb, tcp_client_recv);
    
    return ERR_OK;
}

// --- UDP Logic (Global UDP Relay for SOCKS5) ---
// This thread handles ALL UDP traffic (including DNS) via SOCKS5 UDP Associate
class UdpRelay {
    SOCKET tcpSock;
    SOCKET udpSock;
    uint32_t relay_ip;
    uint16_t relay_port;
    std::atomic<bool> running;
    std::thread th;
    
public:
    UdpRelay() : tcpSock(INVALID_HANDLE_VALUE), udpSock(INVALID_HANDLE_VALUE), running(false) {}
    
    void Start() {
        if (!running) {
            running = true;
            th = std::thread(&UdpRelay::Loop, this);
            th.detach();
        }
    }

    void Send(const uint8_t* data, int len, uint32_t daddr, uint16_t dport) {
        if (!running || udpSock == INVALID_HANDLE_VALUE) return; 
        
        std::vector<uint8_t> buf(10 + len);
        buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 1; // IPv4
        *(uint32_t*)&buf[4] = daddr; // Original Dest IP
        *(uint16_t*)&buf[8] = dport; // Original Dest Port (Net Order)
        memcpy(&buf[10], data, len);
        
        sockaddr_in remote;
        remote.sin_family = AF_INET;
        remote.sin_addr.S_un.S_addr = relay_ip;
        remote.sin_port = relay_port;
        
        sendto(udpSock, (char*)buf.data(), (int)buf.size(), 0, (sockaddr*)&remote, sizeof(remote));
    }

private:
    bool RecvAll(SOCKET s, char* buf, int len) {
        int total = 0;
        while (total < len) {
            int r = recv(s, buf + total, len - total, 0);
            if (r <= 0) return false;
            total += r;
        }
        return true;
    }

    void Loop() {
        while (running) {
            if (tcpSock != INVALID_HANDLE_VALUE) closesocket(tcpSock);
            if (udpSock != INVALID_HANDLE_VALUE) closesocket(udpSock);
            
            tcpSock = socket(AF_INET, SOCK_STREAM, 0);
            udpSock = socket(AF_INET, SOCK_DGRAM, 0);
            
            sockaddr_in local = {0};
            local.sin_family = AF_INET;
            local.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
            bind(udpSock, (sockaddr*)&local, sizeof(local));
            
            sockaddr_in my_udp_addr;
            int len = sizeof(my_udp_addr);
            getsockname(udpSock, (sockaddr*)&my_udp_addr, &len);
            my_udp_addr.sin_addr.S_un.S_addr = ::inet_addr("127.0.0.1"); 

            sockaddr_in proxy_addr;
            proxy_addr.sin_family = AF_INET;
            proxy_addr.sin_addr.S_un.S_addr = ::inet_addr(PROXY_IP);
            proxy_addr.sin_port = ::htons(PROXY_PORT);
            
            if (connect(tcpSock, (sockaddr*)&proxy_addr, sizeof(proxy_addr)) != 0) {
                log_debug("UDP Relay TCP connect failed\n");
                Sleep(2000); continue;
            }
            
            send(tcpSock, "\x05\x01\x00", 3, 0);
            char buf[2048];
            if (!RecvAll(tcpSock, buf, 2) || buf[1] != 0) { Sleep(1000); continue; }
            
            uint8_t req[10] = { 0x05, 0x03, 0x00, 0x01 };
            *(uint32_t*)&req[4] = my_udp_addr.sin_addr.S_un.S_addr;
            *(uint16_t*)&req[8] = my_udp_addr.sin_port;
            send(tcpSock, (char*)req, 10, 0);
            
            if (!RecvAll(tcpSock, buf, 4) || buf[1] != 0) { Sleep(1000); continue; }
            
            uint32_t rip = 0; uint16_t rport = 0;
            if (buf[3] == 1) { 
                RecvAll(tcpSock, buf, 6);
                rip = *(uint32_t*)buf;
                rport = *(uint16_t*)(buf+4);
            } else if (buf[3] == 3) { 
                RecvAll(tcpSock, buf, 1);
                int dlen = buf[0];
                RecvAll(tcpSock, buf, dlen + 2);
                rip = ::inet_addr(PROXY_IP); 
                rport = *(uint16_t*)(buf+dlen);
            } else { Sleep(1000); continue; }
            
            if (rip == 0) rip = ::inet_addr(PROXY_IP);
            
            relay_ip = rip;
            relay_port = rport;
            log_debug("[UDP] Relay Ready at %s:%d\n", PROXY_IP, ::ntohs(rport));
            
            while (running) {
                fd_set rds; FD_ZERO(&rds); 
                FD_SET(tcpSock, &rds);
                FD_SET(udpSock, &rds);
                
                if (select(0, &rds, NULL, NULL, NULL) <= 0) break;
                
                if (FD_ISSET(tcpSock, &rds)) break;
                
                if (FD_ISSET(udpSock, &rds)) {
                    int r = recvfrom(udpSock, buf, 2048, 0, NULL, NULL);
                    if (r > 10 && buf[2] == 0) {
                        int offset = (buf[3] == 1) ? 10 : ((buf[3] == 4) ? 22 : 0);
                        if (offset > 0) {
                            // This part is complex: needs NAT table for UDP replies.
                            // For simplicity, we'll drop UDP packets that are not DNS for now.
                            // A full UDP NAT implementation is beyond the scope of this snippet.
                        }
                    }
                }
            }
        }
    }
};

// Output function
er_t tap_linkoutput(struct netif* netif, struct pbuf* p) {
    uint8_t buf[2048];
    int len = pbuf_copy_partial(p, buf, sizeof(buf), 0);
    
    if (len > 34) {
        struct ip_hdr* ip = (struct ip_hdr*)(buf + 14);
        if (IPH_PROTO(ip) == IP_PROTO_TCP) {
            uint8_t* tcp_base = buf + 14 + IPH_HL(ip) * 4;
            uint16_t dst_port = *(uint16_t*)(tcp_base + 2); 
            
            std::lock_guard<std::mutex> lk(g_nat_mtx);
            auto it = g_nat_table.find(ntohs(dst_port));
            if (it != g_nat_table.end()) {
                ip->src.addr = it->second.original_dst_ip;
                *(uint16_t*)(tcp_base) = it->second.original_dst_port;
                IPH_CHKSUM_SET(ip, 0);
                IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
            }
        }
    }
    DWORD written;
    WriteFile(g_tap, buf, len, &written, NULL);
    return ERR_OK;
}

// Handle UDP (DNS Direct + Generic Drop for now to save space, or Direct for all?)
void udp_direct_thread(std::vector<uint8_t> pkt, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, 0);
    DWORD timeout = 2000;
    setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.S_un.S_addr = dst_ip; 
    dest.sin_port = dst_port;

    sendto(udp, (char*)pkt.data(), (int)pkt.size(), 0, (sockaddr*)&dest, sizeof(dest));

    char buf[2048];
    sockaddr_in from;
    int fromlen = sizeof(from);
    int r = recvfrom(udp, buf, sizeof(buf), 0, (sockaddr*)&from, &fromlen);
    if (r > 0) {
        uint8_t frame[2048];
        memcpy(frame, TAP_MAC, 6); memcpy(frame + 6, TAP_MAC, 6); *(uint16_t*)(frame + 12) = htons(0x0800);
        uint8_t* ip = frame + 14;
        uint8_t* udp_hdr = ip + 20;
        
        memset(ip, 0, 20);
        ip[0] = 0x45;
        *(uint16_t*)(ip + 2) = htons((uint16_t)(20 + 8 + r));
        ip[8] = 64; ip[9] = 17; 
        
        *(uint32_t*)(ip + 12) = from.sin_addr.S_un.S_addr;   
        *(uint32_t*)(ip + 16) = src_ip;  
        *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

        *(uint16_t*)(udp_hdr + 0) = from.sin_port;
        *(uint16_t*)(udp_hdr + 2) = src_port;
        *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + r));
        *(uint16_t*)(udp_hdr + 6) = 0; 
        
        memcpy(udp_hdr + 8, buf, r);
        *(uint16_t*)(udp_hdr + 6) = 0; 

        DWORD written;
        WriteFile(g_tap, frame, 14 + 20 + 8 + r, &written, NULL);
    }
    closesocket(udp);
}

void process_tap_frame(uint8_t* buf, int len) {
    if (len < 14) return;
    uint16_t eth_type = ntohs(*(uint16_t*)(buf + 12));

    if (eth_type == 0x0806) {
        struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        if (p) {
            pbuf_take(p, buf, len);
            if (g_netif.input(p, &g_netif) != ERR_OK) pbuf_free(p);
        }
        return; 
    }

    struct ip_hdr* ip = (struct ip_hdr*)(buf + 14);
    
    if (eth_type == 0x0800 && IPH_V(ip) == 4 && IPH_PROTO(ip) == IP_PROTO_UDP) {
        uint8_t* udp = buf + 14 + IPH_HL(ip) * 4;
        uint16_t dport = *(uint16_t*)(udp + 2);
        uint8_t* payload = udp + 8;
        int pay_len = len - (14 + IPH_HL(ip) * 4 + 8);
        if (pay_len > 0) {
            std::vector<uint8_t> data(payload, payload + pay_len);
            std::thread(udp_direct_thread, data, ip->src.addr, *(uint16_t*)udp, ip->dest.addr, dport).detach();
        }
        return;
    }

    if (eth_type == 0x0800 && IPH_V(ip) == 4 && IPH_PROTO(ip) == IP_PROTO_TCP) {
        uint8_t* tcp_base = buf + 14 + IPH_HL(ip) * 4;
        uint16_t src_port = *(uint16_t*)(tcp_base); 
        uint16_t dst_port = *(uint16_t*)(tcp_base + 2);
        uint32_t dst_ip = ip->dest.addr;

        {
            std::lock_guard<std::mutex> lk(g_nat_mtx);
            NatEntry& e = g_nat_table[ntohs(src_port)]; 
            e.original_dst_ip = dst_ip;
            e.original_dst_port = dst_port; 
            e.last_active = get_now_ms();
        }

        ip->dest.addr = inet_addr(TAP_GW);
        *(uint16_t*)(tcp_base + 2) = htons(LWIP_LISTEN_PORT);

        IPH_CHKSUM_SET(ip, 0);
        IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
        
        struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        pbuf_take(p, buf, len);
        if (g_netif.input(p, &g_netif) != ERR_OK) pbuf_free(p);
    }
}

er_t netif_init_cb(struct netif* netif) {
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
    
    g_tap = CreateFileA(devicePath, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    if (g_tap == INVALID_HANDLE_VALUE) { printf("Error opening TAP\n"); return 1; }

    ULONG status = TRUE; DWORD len;
    DeviceIoControl(g_tap, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL);

    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    lwip_init();

    ip4_addr_t ip, mask, gw;
    ip4addr_aton(TAP_IP, &ip);
    ip4addr_aton(TAP_NETMASK, &mask);
    ip4addr_aton(TAP_GW, &gw);

    netif_add(&g_netif, &ip, &mask, &gw, NULL, netif_init_cb, ethernet_input);
    netif_set_default(&g_netif);

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

    while (true) {
        if (!pending) {
            if (!ReadFile(g_tap, buffer, sizeof(buffer), &bytesRead, &ol)) {
                if (GetLastError() != ERROR_IO_PENDING) break;
                pending = true;
            } else {
                process_tap_frame(buffer, bytesRead);
                pending = false; 
                ol.Offset = 0; ol.OffsetHigh = 0; 
            }
        }

        if (pending) {
            if (WaitForSingleObject(ol.hEvent, 5) == WAIT_OBJECT_0) {
                if (GetOverlappedResult(g_tap, &ol, &bytesRead, FALSE)) {
                    process_tap_frame(buffer, bytesRead);
                }
                pending = false;
                ResetEvent(ol.hEvent);
                ol.Offset = 0; ol.OffsetHigh = 0;
            }
        }
        sys_check_timeouts();
    }
    return 0;
}
