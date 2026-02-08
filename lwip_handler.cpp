#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "winpkfilter_driver.h"
#include "nat_table.h"
#include "lwip_handler.h"
#include "app_config.h"
#include "proxy_udp.h"
#include "dhcp_server.h"
#include <vector>
#include <iostream>
#include <stdarg.h>
#include <cstring>

// Include LwIP ethernet protocol headers
#include "lwip/prot/ethernet.h"
#include "lwip/etharp.h"

std::recursive_mutex g_lwip_mtx;
struct netif g_netif;
uint8_t HOST_MAC[6] = { 0 }; 
bool g_host_mac_known = false;

WinPkFilterDriver* g_winpkfilter_driver = nullptr;

void set_winpkfilter_driver(WinPkFilterDriver* driver) {
    g_winpkfilter_driver = driver;
}

// --- Logging for LwIP ---
uint32_t get_now_ms() { return (uint32_t)GetTickCount64(); }
extern "C" u32_t sys_now() { return get_now_ms(); }
extern "C" unsigned int sys_win_rand() { return (unsigned int)rand(); }
extern "C" void lwip_win32_platform_diag(const char *format, ...) {
    va_list ap; va_start(ap, format); 
    char buf[1024]; vsnprintf(buf, sizeof(buf), format, ap);
    OutputDebugStringA(buf); va_end(ap);
}

extern "C" const char* lwip_strerr(int8_t err) {
    return "LwIP_Error";
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

void recalculate_tcp_checksum(struct ip_hdr* ip, uint8_t* tcp_base, int tcp_len) {
    *(uint16_t*)(tcp_base + 16) = 0;
    uint32_t sum = 0;
    uint16_t* ip_src = (uint16_t*)&ip->src.addr;
    sum += ip_src[0]; sum += ip_src[1];
    uint16_t* ip_dst = (uint16_t*)&ip->dest.addr;
    sum += ip_dst[0]; sum += ip_dst[1];
    sum += ::htons(IP_PROTO_TCP);
    sum += ::htons((uint16_t)tcp_len);
    uint32_t raw_sum = 0;
    uint16_t* ptr = (uint16_t*)tcp_base;
    int l = tcp_len;
    while (l > 1) { raw_sum += *ptr++; l -= 2; }
    if (l > 0) { raw_sum += (uint16_t)(*(const uint8_t*)ptr); }
    sum += raw_sum;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    *(uint16_t*)(tcp_base + 16) = (uint16_t)~sum;
}

err_t winpkfilter_linkoutput(struct netif* netif, struct pbuf* p) {
    if (!g_winpkfilter_driver) return ERR_IF;

    static std::vector<uint8_t> buf;
    buf.resize(p->tot_len);
    pbuf_copy_partial(p, buf.data(), p->tot_len, 0);

    if (!g_winpkfilter_driver->send_to_adapter((const char*)buf.data(), buf.size())) {
        return ERR_IF;
    }

    return ERR_OK;
}

err_t netif_init_cb(struct netif* netif) {
    netif->linkoutput = winpkfilter_linkoutput;
    netif->output = etharp_output; 
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP | NETIF_FLAG_ETHERNET;
    netif->hwaddr_len = 6;
    memset(netif->hwaddr, 0x02, 6); 

    return ERR_OK;
}

void process_ethernet_frame(const char* packet, size_t length, bool outbound) {
    if (length < sizeof(struct eth_hdr) || length > 1514) return;

    if (outbound) {
        return;
    }

    struct eth_hdr* eth = (struct eth_hdr*)packet;
    uint16_t eth_type = ntohs(eth->type);
    
    const uint8_t* smac = (const uint8_t*)&eth->src;
    const uint8_t* dmac = (const uint8_t*)&eth->dest;

    if (eth_type == ETHTYPE_IP) {
        struct ip_hdr* ip = (struct ip_hdr*)(packet + sizeof(struct eth_hdr));
        int ip_payload_len = (int)length - (int)sizeof(struct eth_hdr);

        if (IPH_V(ip) == 4) {
            if (IPH_PROTO(ip) == IP_PROTO_UDP) {
                uint8_t* udp_ptr = (uint8_t*)ip + IPH_HL(ip) * 4;
                uint16_t src_port_h = ntohs(*(uint16_t*)(udp_ptr + 0));
                uint16_t dst_port_h = ntohs(*(uint16_t*)(udp_ptr + 2));

                if (dst_port_h == 67 && g_dhcp_server_ptr) {
                    sockaddr_in client_sa;
                    memset(&client_sa, 0, sizeof(client_sa));
                    client_sa.sin_family = AF_INET;
                    client_sa.sin_addr.S_un.S_addr = ip->src.addr;
                    g_dhcp_server_ptr->handle_request((const char*)udp_ptr + 8, ip_payload_len - (IPH_HL(ip) * 4 + 8), client_sa);
                    return; 
                }

                NatTable::instance().set(ip->src.addr, src_port_h, ip->dest.addr, dst_port_h, smac, dmac);
            }
            else if (IPH_PROTO(ip) == IP_PROTO_TCP) {
                uint8_t* tcp_ptr = (uint8_t*)ip + IPH_HL(ip) * 4;
                uint16_t src_port_h = ntohs(*(uint16_t*)(tcp_ptr + 0));
                uint16_t dst_port_h = ntohs(*(uint16_t*)(tcp_ptr + 2));
                
                NatTable::instance().set(ip->src.addr, src_port_h, ip->dest.addr, dst_port_h, smac, dmac);
            }
        }
    }

    struct pbuf* p = pbuf_alloc(PBUF_RAW, (uint16_t)length, PBUF_POOL);
    if (p) {
        pbuf_take(p, packet, (uint16_t)length);
        if (g_netif.input(p, &g_netif) != ERR_OK) {
            pbuf_free(p);
        }
    }
}
