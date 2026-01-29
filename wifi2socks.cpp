#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX
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
// Explicitly declare ethernet_input for raw frames
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
uint8_t TAP_MAC[6] = { 0x00, 0xFF, 0x92, 0xEA, 0x69, 0x5C }; // Real MAC

// --- Global NAT Table ---
struct NatEntry {
    uint32_t original_dst_ip;
    uint16_t original_dst_port;
    uint64_t last_active;
};
std::map<uint16_t, NatEntry> g_nat_table;
std::mutex g_nat_mtx;

// --- Forward Declarations ---
void handle_arp_manual(uint8_t* buf, int len);
void tap_send_async(const uint8_t* buf, int len);
err_t tap_linkoutput(struct netif* netif, struct pbuf* p);

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

// --- Manual Checksum Implementation ---
uint16_t checksum_raw_buffer(const void* data, int len) {
    uint32_t sum = 0;
    const uint16_t* ptr = (const uint16_t*)data;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0) {
        uint16_t temp = 0;
        *(uint8_t*)&temp = *(const uint8_t*)ptr;
        sum += temp;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

void recalculate_tcp_checksum(struct ip_hdr* ip, uint8_t* tcp_base, int tcp_len) {
    *(uint16_t*)(tcp_base + 16) = 0;

    uint32_t sum = 0;
    // Pseudo Header: Source IP
    uint16_t* ip_src = (uint16_t*)&ip->src.addr;
    sum += ip_src[0];
    sum += ip_src[1];
    
    // Pseudo Header: Dest IP
    uint16_t* ip_dst = (uint16_t*)&ip->dest.addr;
    sum += ip_dst[0];
    sum += ip_dst[1];

    // Pseudo Header: Protocol (0x0006 in Network Order)
    sum += ::htons(IP_PROTO_TCP); 

    // Pseudo Header: Length
    sum += ::htons((uint16_t)tcp_len);

    // TCP Segment
    sum += checksum_raw_buffer(tcp_base, tcp_len);

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    *(uint16_t*)(tcp_base + 16) = (uint16_t)~sum;
}

// --- ASYNC WRITE HELPER ---
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

void handle_arp_manual(uint8_t* buf, int len) {
    if (len < sizeof(EthHeader) + sizeof(ArpPacket)) return;

    EthHeader* eth = (EthHeader*)buf;
    ArpPacket* arp = (ArpPacket*)(buf + sizeof(EthHeader));

    if (::ntohs(arp->htype) != 1 || ::ntohs(arp->ptype) != 0x0800 || 
        arp->hlen != 6 || arp->plen != 4) return;

    uint16_t oper = ::ntohs(arp->oper);
    if (oper != 1) return; 

    uint32_t target_ip = arp->tpa;
    uint32_t my_ip = ::inet_addr(TAP_GW);
    
    if (target_ip != my_ip) return;

    memcpy(eth->dst_mac, eth->src_mac, 6);
    memcpy(eth->src_mac, TAP_MAC, 6);
    
    arp->oper = ::htons(2); 
    
    memcpy(arp->tha, arp->sha, 6);
    arp->tpa = arp->spa;
    
    memcpy(arp->sha, TAP_MAC, 6);
    arp->spa = my_ip;

    tap_send_async(buf, len);
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

// --- SNI Parser ---
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



// --- Thread Safety ---
std::recursive_mutex g_lwip_mtx;

// --- TCP Logic ---
struct TcpCtx {
    struct tcp_pcb* client_pcb;
    SOCKET proxy_socket;
    std::atomic<bool> closed;
    std::atomic<bool> connected;
    NatEntry target;
    std::vector<uint8_t> sni_buffer;
    std::vector<uint8_t> upstream_data;
    std::mutex data_mtx;

    TcpCtx() : client_pcb(NULL), proxy_socket(INVALID_SOCKET), closed(false), connected(false) {
        sni_buffer.reserve(MAX_SNI_LEN);
        upstream_data.reserve(4096);
    }
};

void close_tcp_ctx(TcpCtx* ctx) {
    if (!ctx || ctx->closed.exchange(true)) return;
    std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
    if (ctx->client_pcb) {
        tcp_arg(ctx->client_pcb, NULL);
        tcp_recv(ctx->client_pcb, NULL);
        tcp_err(ctx->client_pcb, NULL);
        tcp_close(ctx->client_pcb);
        ctx->client_pcb = NULL;
    }
    if (ctx->proxy_socket != INVALID_SOCKET) {
        closesocket(ctx->proxy_socket);
        ctx->proxy_socket = INVALID_SOCKET;
    }
}

void proxy_reader_loop(TcpCtx* ctx) {
    char buf[16384];
    while (!ctx->closed) {
        int r = recv(ctx->proxy_socket, buf, sizeof(buf), 0);
        if (r <= 0) break;
        std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
        if (ctx->client_pcb && !ctx->closed) {
            if (tcp_write(ctx->client_pcb, buf, (u16_t)r, 1) == ERR_OK) {
                tcp_output(ctx->client_pcb);
            } else break;
        } else break;
    }
    close_tcp_ctx(ctx);
}

void proxy_init_thread(TcpCtx* ctx) {
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.S_un.S_addr = inet_addr(PROXY_IP);
    addr.sin_port = htons(PROXY_PORT);

    if (connect(ctx->proxy_socket, (sockaddr*)&addr, sizeof(addr)) == 0) {
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
        send(ctx->proxy_socket, cmd, (int)strlen(cmd), 0);

        char resp[1024];
        recv(ctx->proxy_socket, resp, sizeof(resp), 0);

        {
            std::lock_guard<std::mutex> lock(ctx->data_mtx);
            if (!ctx->upstream_data.empty()) {
                send(ctx->proxy_socket, (const char*)ctx->upstream_data.data(), (int)ctx->upstream_data.size(), 0);
                ctx->upstream_data.clear();
            }
            ctx->connected = true;
        }
        proxy_reader_loop(ctx);
    } else {
        close_tcp_ctx(ctx);
    }
}

err_t tcp_client_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    TcpCtx* ctx = (TcpCtx*)arg;
    if (!p) { close_tcp_ctx(ctx); return ERR_OK; }
    tcp_recved(tpcb, p->tot_len);

    if (ctx->connected) {
        send(ctx->proxy_socket, (const char*)p->payload, p->len, 0);
    } else {
        std::lock_guard<std::mutex> lock(ctx->data_mtx);
        if (ctx->connected) {
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
                    ctx->proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
                    std::thread(proxy_init_thread, ctx).detach();
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
    tcp_err(newpcb, [](void* arg, err_t err) { close_tcp_ctx((TcpCtx*)arg); });
    return ERR_OK;
}

// --- DNS Direct ---
std::string parse_dns_name(const uint8_t* buf, int len, int& pos) {
    std::string name;
    int jumps = 0;
    int p = pos;
    while (p < len) {
        uint8_t c = buf[p];
        if (c == 0) { p++; if (jumps == 0) pos = p; return name; }
        if ((c & 0xC0) == 0xC0) { 
            if (p + 1 >= len) return "<err-ptr-len>";
            int offset = ((c & 0x3F) << 8) | buf[p + 1];
            if (jumps == 0) pos = p + 2;
            p = offset;
            jumps++; if (jumps > 10) return "<err-loop>";
        } else { 
            if (p + 1 + c > len) return "<err-label-len>";
            if (!name.empty()) name += ".";
            name.append((char*)buf + p + 1, c);
            p += 1 + c;
        }
    }
    return "";
}

void udp_direct_thread(std::vector<uint8_t> pkt, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp == INVALID_SOCKET) return; 
    
    DWORD timeout = 2000;
    setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.S_un.S_addr = dst_ip;
    dest.sin_port = dst_port;

    sendto(udp, (char*)pkt.data(), (int)pkt.size(), 0, (sockaddr*)&dest, sizeof(dest));

    char buf[2048];
    sockaddr_in from_addr;
    int from_len = sizeof(from_addr);
    int r = recvfrom(udp, buf, sizeof(buf), 0, (sockaddr*)&from_addr, &from_len);
    
    if (r > 0) {
        uint8_t frame[2048];
        if (14 + 20 + 8 + r > sizeof(frame)) { closesocket(udp); return; }

        memcpy(frame, TAP_MAC, 6);
        memcpy(frame + 6, TAP_MAC, 6);
        *(uint16_t*)(frame + 12) = ::htons(0x0800);

        uint8_t* ip = frame + 14;
        uint8_t* udp_hdr = ip + 20;
        
        memset(ip, 0, 20);
        ip[0] = 0x45;
        *(uint16_t*)(ip + 2) = ::htons((uint16_t)(20 + 8 + r));
        ip[8] = 64; ip[9] = 17; 
        
        *(uint32_t*)(ip + 12) = dst_ip;   
        *(uint32_t*)(ip + 16) = src_ip;  
        *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

        *(uint16_t*)(udp_hdr + 0) = dst_port;
        *(uint16_t*)(udp_hdr + 2) = src_port;
        *(uint16_t*)(udp_hdr + 4) = ::htons((uint16_t)(8 + r));
        *(uint16_t*)(udp_hdr + 6) = 0; 
        
        memcpy(udp_hdr + 8, buf, r);

        tap_send_async(frame, 14 + 20 + 8 + r);
    }
    closesocket(udp);
}

// --- Main Processing ---
void process_tap_frame(uint8_t* buf, int len) {
    if (len < 14) return;
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
    
    // Check if it's IPv4
    if (IPH_V(ip) == 4) {
        // UDP Direct Handler (Generic)
        if (IPH_PROTO(ip) == IP_PROTO_UDP) {
            uint8_t* udp = buf + 14 + IPH_HL(ip) * 4;
            uint16_t src_port = *(uint16_t*)(udp + 0);
            uint16_t dst_port = *(uint16_t*)(udp + 2);
            uint8_t* payload = udp + 8;
            int pay_len = len - (14 + IPH_HL(ip) * 4 + 8);
            
            if (pay_len >= 0) {
                std::vector<uint8_t> data(payload, payload + pay_len);
                std::thread(udp_direct_thread, data, ip->src.addr, src_port, ip->dest.addr, dst_port).detach();
            }
            return; // Don't pass UDP to LwIP
        }

        // TCP NAT Logic
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
                log_debug("[NAT] Added/Updated entry for client port %d -> %08x:%d\n", ::ntohs(src_port), dst_ip, dst_port);
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

        // Pass TCP and ICMP to LwIP
        struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        if (p) {
            pbuf_take(p, buf, len);
            err_t err = g_netif.input(p, &g_netif);
            if (err != ERR_OK) {
                printf("[LwIP-IN] Input failed: %d\n", err);
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
            DWORD waitRes = WaitForSingleObject(ol.hEvent, 5); 
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
    }
    return 0;
}