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

#pragma comment(lib, "Ws2_32.lib")

// --- CONFLICT RESOLUTION ---
// Rename LwIP structs/funcs to avoid collision with Windows
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

// Undefine Macros that break LwIP structs
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

// Restore/Undefine
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
#define PROXY_PORT      3080
#define LWIP_LISTEN_PORT 7000

#define TAP_CONTROL_CODE(request, method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)

// FIXED: Remove "Global" prefix for better compatibility
#define TAP_WIN_PATH "\\\\.\\%s.tap"

// --- Headers for Manual Processing ---
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

// --- Debug Logging ---
void log_debug(const char* format, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    
    // Output to VS Debugger Window
    OutputDebugStringA(buf);
    // Output to Console
    printf("%s", buf);
}

// --- Platform Helper ---
uint32_t get_now_ms() { return (uint32_t)GetTickCount64(); }
extern "C" u32_t sys_now() { return get_now_ms(); }
extern "C" unsigned int sys_win_rand() { return (unsigned int)rand(); }
extern "C" void lwip_win32_platform_diag(const char *format, ...) {
    va_list ap; va_start(ap, format); 
    char buf[1024]; vsnprintf(buf, sizeof(buf), format, ap);
    OutputDebugStringA(buf); 
    va_end(ap);
}

// --- ASYNC WRITE HELPER ---
std::mutex g_write_mtx;
void tap_send_async(const uint8_t* buf, int len) {
    if (len <= 0) return; 
    
    // Protect overlapping writes if needed, though OVERLAPPED struct usually handles it per call
    std::lock_guard<std::mutex> lk(g_write_mtx);

    // Need to keep OVERLAPPED structure valid until completion? 
    // Wait, if we use a local variable and wait, it's fine.
    // Ideally we queue writes and have a write thread, but for quick fix, let's do Wait. 
    
    OVERLAPPED ol = {0};
    ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ol.hEvent) {
        log_debug("CreateEvent failed for write\n");
        return;
    }

    DWORD written = 0;
    // Note: WriteFile returns FALSE if IO is pending (normal for Overlapped)
    if (!WriteFile(g_tap, buf, len, &written, &ol)) {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            // Wait for completion (Blocking here is fine for now as writing is usually fast, 
            // or we could optimize queueing later. LwIP expects linkoutput to be synchronous-ish)
            if (WaitForSingleObject(ol.hEvent, 1000) == WAIT_OBJECT_0) {
                GetOverlappedResult(g_tap, &ol, &written, FALSE);
            } else {
                log_debug("Write timeout/failed\n");
                CancelIo(g_tap);
            }
        } else {
            log_debug("WriteFile failed imm. Err=%d\n", err);
        }
    }
    CloseHandle(ol.hEvent);
}

// --- Helper Functions ---
// Checksum helper
uint16_t ip_chksum_simple(void* dataptr, int len) {
    uint32_t acc = 0;
    uint16_t* ptr = (uint16_t*)dataptr;
    while (len > 1) { acc += *ptr++; len -= 2; }
    if (len == 1) acc += *(uint8_t*)ptr;
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)~(acc);
}

// DNS Parser (Minimal)
std::string parse_dns_name(const uint8_t* buf, int len, int& pos) {
    std::string name;
    int jumps = 0;
    int p = pos;
    while (p < len) {
        uint8_t c = buf[p];
        if (c == 0) { p++; if (jumps == 0) pos = p; return name; }
        if ((c & 0xC0) == 0xC0) { 
            if (p + 1 >= len) return "<err>";
            int offset = ((c & 0x3F) << 8) | buf[p + 1];
            if (jumps == 0) pos = p + 2;
            p = offset;
            jumps++; if (jumps > 10) return "<loop>";
        } else { 
            if (p + 1 + c > len) return "<err>";
            if (!name.empty()) name += ".";
            name.append((char*)buf + p + 1, c);
            p += 1 + c;
        }
    }
    return "";
}

// --- Manual ARP Handling ---
void handle_arp_manual(uint8_t* buf, int len) {
    if (len < sizeof(EthHeader) + sizeof(ArpPacket)) return;

    EthHeader* eth = (EthHeader*)buf;
    ArpPacket* arp = (ArpPacket*)(buf + sizeof(EthHeader));

    if (::ntohs(arp->oper) != 1) return;

    // Check if asking for Gateway IP
    // FIXED: Use .S_un.S_addr
    if (arp->tpa != ::inet_addr(TAP_GW)) return;

    log_debug("[ARP] Request for %s from %02X:%02X:%02X:%02X:%02X:%02X\n", 
        TAP_GW, arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);

    uint8_t reply[64]; 
    memset(reply, 0, sizeof(reply)); // Padding with zeros

    EthHeader* reth = (EthHeader*)reply;
    ArpPacket* rarp = (ArpPacket*)(reply + sizeof(EthHeader));

    memcpy(reth->dst_mac, eth->src_mac, 6);
    memcpy(reth->src_mac, TAP_MAC, 6);
    reth->type = eth->type;

    rarp->htype = arp->htype;
    rarp->ptype = arp->ptype;
    rarp->hlen = 6;
    rarp->plen = 4;
    rarp->oper = ::htons(2);

    memcpy(rarp->sha, TAP_MAC, 6);
    // FIXED: Use .S_un.S_addr
    rarp->spa = ::inet_addr(TAP_GW);

    memcpy(rarp->tha, arp->sha, 6);
    rarp->tpa = arp->spa;

    // FIXED: Use Async Write Helper
    tap_send_async(reply, 42); 
    log_debug("[ARP] Replied: I am %s\n", TAP_GW);
}

// --- NAT & SOCKS5 Logic ---
struct NatEntry {
    uint32_t original_dst_ip;
    uint16_t original_dst_port;
    uint64_t last_active;
};
std::map<uint16_t, NatEntry> g_nat_table;
std::mutex g_nat_mtx;

enum SocksState { STATE_NONE, STATE_HANDSHAKE_SENT, STATE_REQUEST_SENT, STATE_ESTABLISHED };
struct ConnectionCtx {
    struct tcp_pcb* client_pcb; 
    struct tcp_pcb* proxy_pcb; 
    SocksState state;
    NatEntry target;
    std::vector<uint8_t> pending_client_data; 
    ConnectionCtx() : client_pcb(NULL), proxy_pcb(NULL), state(STATE_NONE) {}
};

// --- LwIP Callbacks (SOCKS5 Logic) ---

err_t proxy_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    ConnectionCtx* ctx = (ConnectionCtx*)arg;
    if (!p) { 
        if (ctx->client_pcb) { tcp_arg(ctx->client_pcb, NULL); tcp_close(ctx->client_pcb); ctx->client_pcb = NULL; }
        tcp_close(tpcb); delete ctx; return ERR_OK;
    }
    tcp_recved(tpcb, p->tot_len);

    if (ctx->state == STATE_ESTABLISHED) {
        if (ctx->client_pcb) {
            tcp_write(ctx->client_pcb, p->payload, p->len, 1);
            tcp_output(ctx->client_pcb);
        }
    } else if (ctx->state == STATE_HANDSHAKE_SENT) {
        uint8_t* d = (uint8_t*)p->payload;
        if (p->len >= 2 && d[1] == 0x00) {
            uint8_t req[10] = { 0x05, 0x01, 0x00, 0x01 };
            *(uint32_t*)(req + 4) = ctx->target.original_dst_ip; 
            *(uint16_t*)(req + 8) = ctx->target.original_dst_port; 
            tcp_write(tpcb, req, 10, 1);
            tcp_output(tpcb);
            ctx->state = STATE_REQUEST_SENT;
        }
    } else if (ctx->state == STATE_REQUEST_SENT) {
        uint8_t* d = (uint8_t*)p->payload;
        if (p->len >= 10 && d[1] == 0x00) {
            ctx->state = STATE_ESTABLISHED;
            if (!ctx->pending_client_data.empty()) {
                tcp_write(tpcb, ctx->pending_client_data.data(), ctx->pending_client_data.size(), 1);
                tcp_output(tpcb);
                ctx->pending_client_data.clear();
            }
        }
    }
    pbuf_free(p);
    return ERR_OK;
}

err_t client_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    ConnectionCtx* ctx = (ConnectionCtx*)arg;
    if (!p) { 
        if (ctx->proxy_pcb) { tcp_close(ctx->proxy_pcb); ctx->proxy_pcb = NULL; }
        tcp_close(tpcb); return ERR_OK;
    }
    tcp_recved(tpcb, p->tot_len);

    if (ctx->state == STATE_ESTABLISHED) {
        if (ctx->proxy_pcb) {
            tcp_write(ctx->proxy_pcb, p->payload, p->len, 1);
            tcp_output(ctx->proxy_pcb);
        }
    } else {
        uint8_t* d = (uint8_t*)p->payload;
        ctx->pending_client_data.insert(ctx->pending_client_data.end(), d, d + p->len);
    }
    pbuf_free(p);
    return ERR_OK;
}

err_t proxy_connected(void* arg, struct tcp_pcb* tpcb, err_t err) {
    ConnectionCtx* ctx = (ConnectionCtx*)arg;
    if (err != ERR_OK) return err;
    uint8_t handshake[] = { 0x05, 0x01, 0x00 };
    tcp_write(tpcb, handshake, 3, 1);
    tcp_output(tpcb);
    ctx->state = STATE_HANDSHAKE_SENT;
    return ERR_OK;
}

err_t tcp_proxy_accept(void* arg, struct tcp_pcb* newpcb, err_t err) {
    uint16_t client_port = newpcb->remote_port;
    NatEntry target = { 0 };
    {
        std::lock_guard<std::mutex> lk(g_nat_mtx);
        auto it = g_nat_table.find(ntohs(client_port)); 
        if (it != g_nat_table.end()) target = it->second;
    }
    if (target.original_dst_ip == 0) return ERR_ABRT;

    ConnectionCtx* ctx = new ConnectionCtx();
    ctx->client_pcb = newpcb;
    ctx->target = target;
    tcp_arg(newpcb, ctx);
    tcp_recv(newpcb, client_recv);

    struct tcp_pcb* proxy_pcb = tcp_new();
    ctx->proxy_pcb = proxy_pcb;
    tcp_arg(proxy_pcb, ctx);
    tcp_recv(proxy_pcb, proxy_recv);
    
    ip_addr_t proxy_ip;
    // FIXED: Use .S_un.S_addr
    ip4_addr_set_u32(&proxy_ip, ::inet_addr(PROXY_IP)); 
    tcp_connect(proxy_pcb, &proxy_ip, PROXY_PORT, proxy_connected);
    return ERR_OK;
}

err_t tap_linkoutput(struct netif* netif, struct pbuf* p) {
    uint8_t buf[2048];
    int len = pbuf_copy_partial(p, buf, sizeof(buf), 0);
    
    if (len > 34) {
        struct ip_hdr* ip = (struct ip_hdr*)(buf + 14);
        if (IPH_PROTO(ip) == IP_PROTO_TCP) {
            uint8_t* tcp_base = buf + 14 + IPH_HL(ip) * 4;
            uint16_t dst_port = *(uint16_t*)(tcp_base + 2); 
            uint16_t port_key = ::ntohs(dst_port); 

            std::lock_guard<std::mutex> lk(g_nat_mtx);
            auto it = g_nat_table.find(port_key);
            if (it != g_nat_table.end()) {
                ip->src.addr = it->second.original_dst_ip;
                *(uint16_t*)(tcp_base) = it->second.original_dst_port;
                IPH_CHKSUM_SET(ip, 0);
                IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
            }
        }
    }
    // FIXED: Use Async Write Helper
    tap_send_async(buf, len);
    return ERR_OK;
}

// Thread to handle DNS Direct
void dns_direct_thread(std::vector<uint8_t> pkt, uint32_t src_ip, uint16_t src_port) {
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp == INVALID_SOCKET) return; 
    
    DWORD timeout = 2000;
    setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    sockaddr_in dest;
    dest.sin_family = AF_INET;
    // FIXED: Use .S_un.S_addr
    dest.sin_addr.S_un.S_addr = ::inet_addr("8.8.8.8");
    dest.sin_port = ::htons(53);

    sendto(udp, (char*)pkt.data(), (int)pkt.size(), 0, (sockaddr*)&dest, sizeof(dest));

    char buf[2048];
    int r = recvfrom(udp, buf, sizeof(buf), 0, NULL, NULL);
    if (r > 0) {
        if (r > 12) { 
             int pos = 12; 
             std::string qname = parse_dns_name((uint8_t*)buf, r, pos);
             printf("[DNS-DIRECT] %s (via 8.8.8.8)\n", qname.c_str());
        }

        uint8_t frame[2048];
        memcpy(frame, TAP_MAC, 6);
        memcpy(frame + 6, TAP_MAC, 6);
        *(uint16_t*)(frame + 12) = ::htons(0x0800);

        uint8_t* ip = frame + 14;
        uint8_t* udp_hdr = ip + 20;
        
        memset(ip, 0, 20);
        ip[0] = 0x45;
        *(uint16_t*)(ip + 2) = ::htons((uint16_t)(20 + 8 + r));
        ip[8] = 64; ip[9] = 17; 
        
        // FIXED: Use .S_un.S_addr
        *(uint32_t*)(ip + 12) = dest.sin_addr.S_un.S_addr;   
        *(uint32_t*)(ip + 16) = src_ip;  
        *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

        *(uint16_t*)(udp_hdr + 0) = dest.sin_port;
        *(uint16_t*)(udp_hdr + 2) = src_port;
        *(uint16_t*)(udp_hdr + 4) = ::htons((uint16_t)(8 + r));
        *(uint16_t*)(udp_hdr + 6) = 0; 
        
        memcpy(udp_hdr + 8, buf, r);
        *(uint16_t*)(udp_hdr + 6) = 0; 

        // FIXED: Use Async Write Helper
        tap_send_async(frame, 14 + 20 + 8 + r);
    }
    closesocket(udp);
}

void process_tap_frame(uint8_t* buf, int len) {
    if (len < 14) return;
    uint16_t eth_type = ::ntohs(*(uint16_t*)(buf + 12));

    if (eth_type == 0x0806) {
        handle_arp_manual(buf, len);
        return; 
    }

    struct ip_hdr* ip = (struct ip_hdr*)(buf + 14);
    
    // 1. DNS Direct Intercept
    if (IPH_V(ip) == 4 && IPH_PROTO(ip) == IP_PROTO_UDP) {
        uint8_t* udp = buf + 14 + IPH_HL(ip) * 4;
        uint16_t dport = *(uint16_t*)(udp + 2);
        if (::ntohs(dport) == 53) {
            uint8_t* payload = udp + 8;
            int pay_len = len - (14 + IPH_HL(ip) * 4 + 8);
            if (pay_len > 0) {
                std::vector<uint8_t> data(payload, payload + pay_len);
                std::thread(dns_direct_thread, data, ip->src.addr, *(uint16_t*)udp).detach();
            }
            return; 
        }
    }

    // 2. TCP NAT
    if (IPH_V(ip) == 4 && IPH_PROTO(ip) == IP_PROTO_TCP) {
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

        // FIXED: Use .S_un.S_addr
        ip->dest.addr = ::inet_addr(TAP_GW);
        *(uint16_t*)(tcp_base + 2) = ::htons(LWIP_LISTEN_PORT);

        IPH_CHKSUM_SET(ip, 0);
        IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
        
        struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        pbuf_take(p, buf, len);
        if (g_netif.input(p, &g_netif) != ERR_OK) pbuf_free(p);
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
    // FIXED: Use LwIP's ip4addr_aton which handles strings
    ip4addr_aton(TAP_IP, &ip);
    ip4addr_aton(TAP_NETMASK, &mask);
    ip4addr_aton(TAP_GW, &gw);

    netif_add(&g_netif, &ip, &mask, &gw, NULL, netif_init_cb, ethernet_input);
    netif_set_default(&g_netif);

    struct tcp_pcb* pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, LWIP_LISTEN_PORT);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, tcp_proxy_accept);

    log_debug("LwIP Tun2Socks Running. Proxy: %s:%d\n", PROXY_IP, PROXY_PORT);

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
                process_tap_frame(buffer, bytesRead);
                pending = false; 
                ol.Offset = 0; ol.OffsetHigh = 0; 
            }
        }

        if (pending) {
            DWORD waitRes = WaitForSingleObject(ol.hEvent, 5); 
            if (waitRes == WAIT_OBJECT_0) {
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