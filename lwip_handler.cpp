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
#include "logger.h"
#include <vector>
#include <iostream>
#include <stdarg.h>
#include <cstring>

#include "lwip/prot/ethernet.h"
#include "lwip/etharp.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"
#include "lwip/raw.h"

std::recursive_mutex g_lwip_mtx;
struct netif g_netif;
uint8_t HOST_MAC[6] = { 0 }; 
bool g_host_mac_known = false;

WinPkFilterDriver* g_winpkfilter_driver = nullptr;

void set_winpkfilter_driver(WinPkFilterDriver* driver) {
    g_winpkfilter_driver = driver;
}

uint32_t get_now_ms() { return (uint32_t)GetTickCount64(); }
extern "C" u32_t sys_now() { return get_now_ms(); }
extern "C" unsigned int sys_win_rand() { return (unsigned int)rand(); }
extern "C" void lwip_win32_platform_diag(const char *format, ...) {
    va_list ap; va_start(ap, format); 
    char buf[1024]; vsnprintf(buf, sizeof(buf), format, ap);
    OutputDebugStringA(buf); va_end(ap);
}

extern "C" const char* lwip_strerr(int8_t err) { return "LwIP_Error"; }

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

void recalculate_udp_checksum(struct ip_hdr* ip, uint8_t* udp_base, int udp_len) {
    *(uint16_t*)(udp_base + 6) = 0;
    uint32_t sum = 0;
    uint16_t* ip_src = (uint16_t*)&ip->src.addr;
    sum += ip_src[0]; sum += ip_src[1];
    uint16_t* ip_dst = (uint16_t*)&ip->dest.addr;
    sum += ip_dst[0]; sum += ip_dst[1];
    sum += ::htons(IP_PROTO_UDP);
    sum += ::htons((uint16_t)udp_len);
    uint32_t raw_sum = 0;
    uint16_t* ptr = (uint16_t*)udp_base;
    int l = udp_len;
    while (l > 1) { raw_sum += *ptr++; l -= 2; }
    if (l > 0) { raw_sum += (uint16_t)(*(const uint8_t*)ptr); }
    sum += raw_sum;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    *(uint16_t*)(udp_base + 6) = (uint16_t)~sum;
}

err_t winpkfilter_linkoutput(struct netif* netif, struct pbuf* p) {
    if (!g_winpkfilter_driver) return ERR_IF;
    static std::vector<uint8_t> buf;
    buf.resize(p->tot_len);
    pbuf_copy_partial(p, buf.data(), p->tot_len, 0);

    if (buf.size() >= sizeof(struct eth_hdr) + 20) {
        struct eth_hdr* eth = (struct eth_hdr*)buf.data();
        if (ntohs(eth->type) == ETHTYPE_IP) {
            struct ip_hdr* ip = (struct ip_hdr*)(buf.data() + sizeof(struct eth_hdr));
            if (IPH_PROTO(ip) == IP_PROTO_TCP) {
                uint8_t* tcp_base = (uint8_t*)ip + IPH_HL(ip) * 4;
                uint16_t src_p = ntohs(*(uint16_t*)tcp_base);
                if (src_p == g_config.lwip_listen_port) {
                    uint16_t dst_p = ntohs(*(uint16_t*)(tcp_base + 2));
                    NatEntry entry = NatTable::instance().get(ip->dest.addr, dst_p);
                    if (entry.original_dst_ip != 0) {
                        ip->src.addr = entry.original_dst_ip;
                        *(uint16_t*)tcp_base = htons(entry.original_dst_port);
                        IPH_CHKSUM_SET(ip, 0);
                        IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
                        recalculate_tcp_checksum(ip, tcp_base, ntohs(IPH_LEN(ip)) - IPH_HL(ip) * 4);
                    }
                }
            }
        }
    }
    g_winpkfilter_driver->send_to_adapter((const char*)buf.data(), buf.size());
    return ERR_OK;
}

static u8_t lwip_udp_raw_recv(void* arg, struct raw_pcb* pcb, struct pbuf* p, const ip_addr_t* addr) {
    if (p != NULL) {
        struct ip_hdr* ip = (struct ip_hdr*)p->payload;
        if (IPH_PROTO(ip) == IP_PROTO_UDP) {
            uint8_t* buf = (uint8_t*)p->payload;
            int len = p->tot_len;
            uint8_t* udp_ptr = buf + IPH_HL(ip) * 4;
            if (len >= IPH_HL(ip) * 4 + 8) {
                uint16_t src_port = *(uint16_t*)(udp_ptr + 0);
                uint16_t dst_port = *(uint16_t*)(udp_ptr + 2);
                NatEntry target = NatTable::instance().get(ip->src.addr, ntohs(src_port));
                uint32_t real_dst_ip = ip->dest.addr;
                uint16_t real_dst_port = dst_port;
                if (target.original_dst_ip != 0) {
                    real_dst_ip = target.original_dst_ip;
                    real_dst_port = htons(target.original_dst_port);
                }
                handle_udp_packet(ip->src.addr, real_dst_ip, src_port, real_dst_port, udp_ptr + 8, len - (IPH_HL(ip) * 4 + 8));
            }
        }
        pbuf_free(p);
        return 1;
    }
    return 0;
}

err_t netif_init_cb(struct netif* netif) {
    netif->linkoutput = winpkfilter_linkoutput;
    netif->output = etharp_output; 
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP | NETIF_FLAG_ETHERNET;
    netif->hwaddr_len = 6;
    struct raw_pcb* pcb = raw_new(IP_PROTO_UDP);
    if (pcb) {
        raw_bind(pcb, IP_ADDR_ANY);
        raw_recv(pcb, lwip_udp_raw_recv, NULL);
        LOG_INFO("[LwIP] Registered UDP raw_pcb.");
    }
    return ERR_OK;
}

void process_ethernet_frame(const char* packet, size_t length, bool outbound) {
    if (length < sizeof(struct eth_hdr) || length > 9014) return;
    if (outbound) {
        struct eth_hdr* eth = (struct eth_hdr*)packet;
        if (ntohs(eth->type) == ETHTYPE_IP) {
            struct ip_hdr* ip = (struct ip_hdr*)(packet + sizeof(struct eth_hdr));
            if (IPH_PROTO(ip) == IP_PROTO_UDP) {
                uint8_t* udp_ptr = (uint8_t*)ip + IPH_HL(ip) * 4;
                if (ntohs(*(uint16_t*)(udp_ptr + 0)) == 67) {
                    ip4_addr_t lwip_ip; ip4addr_aton(g_config.tap_ip.c_str(), &lwip_ip);
                    if (ip->src.addr != lwip_ip.addr) return; 
                }
            }
        }
        if (g_winpkfilter_driver) g_winpkfilter_driver->send_to_adapter(packet, length);
        return;
    }

    static std::vector<uint8_t> buf;
    buf.assign(packet, packet + length);
    struct eth_hdr* eth = (struct eth_hdr*)buf.data();
    
    // --- 修复：入站包必须将目标 MAC 改为 LwIP 接口的 MAC ---
    memcpy(eth->dest.addr, g_netif.hwaddr, 6);

    uint16_t eth_type = ntohs(eth->type);
    const uint8_t* smac = (const uint8_t*)&eth->src;
    const uint8_t* dmac = (const uint8_t*)&eth->dest;

    if (eth_type == ETHTYPE_IP) {
        struct ip_hdr* ip = (struct ip_hdr*)(packet + sizeof(struct eth_hdr));
        int ip_len = (int)buf.size() - (int)sizeof(struct eth_hdr);
        if (IPH_V(ip) == 4) {
            ip4_addr_t lwip_ip; ip4addr_aton(g_config.tap_ip.c_str(), &lwip_ip);

            if (IPH_PROTO(ip) == IP_PROTO_UDP) {
                uint8_t* udp_ptr = (uint8_t*)ip + IPH_HL(ip) * 4;
                uint16_t sp_h = ntohs(*(uint16_t*)(udp_ptr + 0));
                uint16_t dp_h = ntohs(*(uint16_t*)(udp_ptr + 2));
                if (dp_h == 67 && g_dhcp_server_ptr) {
                    sockaddr_in sa; memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET; sa.sin_addr.S_un.S_addr = ip->src.addr;
                    g_dhcp_server_ptr->handle_request((const char*)udp_ptr + 8, ip_len - (IPH_HL(ip) * 4 + 8), sa);
                    return; 
                }
                // --- REDIRECT UDP ---
                NatTable::instance().set(ip->src.addr, sp_h, ip->dest.addr, dp_h, smac, dmac);
                ip->dest.addr = lwip_ip.addr;
                IPH_CHKSUM_SET(ip, 0); IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
                recalculate_udp_checksum(ip, udp_ptr, ip_len - IPH_HL(ip) * 4);
            }
            else if (IPH_PROTO(ip) == IP_PROTO_TCP) {
                uint8_t* tcp_ptr = (uint8_t*)ip + IPH_HL(ip) * 4;
                uint16_t sp_h = ntohs(*(uint16_t*)(tcp_ptr + 0));
                uint16_t dp_h = ntohs(*(uint16_t*)(tcp_ptr + 2));
                NatTable::instance().set(ip->src.addr, sp_h, ip->dest.addr, dp_h, smac, dmac);
                ip->dest.addr = lwip_ip.addr;
                *(uint16_t*)(tcp_ptr + 2) = htons(g_config.lwip_listen_port);
                IPH_CHKSUM_SET(ip, 0); IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
                recalculate_tcp_checksum(ip, tcp_ptr, ip_len - IPH_HL(ip) * 4);
            }
        }
    }

    struct pbuf* p = pbuf_alloc(PBUF_RAW, (uint16_t)buf.size(), PBUF_POOL);
    if (p) {
        pbuf_take(p, buf.data(), (uint16_t)buf.size());
        err_t err = g_netif.input(p, &g_netif);
        if (err != ERR_OK) printf("[LwIP] packet rejected: %d\n", err);
    }
}