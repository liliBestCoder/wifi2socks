#include "lwip_handler.h"
#include "app_config.h"
#include "windivert_driver.h"
#include "nat_table.h"
#include "proxy_udp.h"
#include <vector>
#include <iostream>
#include <stdarg.h>

std::recursive_mutex g_lwip_mtx;
struct netif g_netif;
uint8_t HOST_MAC[6] = { 0 }; 
bool g_host_mac_known = false;

WinDivertDriver* g_windivert_driver = nullptr;
WINDIVERT_ADDRESS g_last_addr; // HACK: Store last packet address. Not thread-safe if LwIP is concurrent.

void set_windivert_driver(WinDivertDriver* driver) {
    g_windivert_driver = driver;
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
    if (len > 0) { sum += (uint16_t)(*(const uint8_t*)ptr); }
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

err_t windivert_linkoutput(struct netif* netif, struct pbuf* p) {
    if (!g_windivert_driver) return ERR_IF;

    // Use a mutable buffer to perform NAT
    static std::vector<uint8_t> buf;
    buf.assign(p->tot_len, 0);
    pbuf_copy_partial(p, buf.data(), p->tot_len, 0);

    if (buf.size() >= 20) {
        struct ip_hdr* ip = (struct ip_hdr*)buf.data();
        if (IPH_V(ip) == 4 && IPH_PROTO(ip) == IP_PROTO_TCP) {
             ip4_addr_t lwip_ip;
             ip4addr_aton("192.168.137.1", &lwip_ip);
             if (ip->src.addr == lwip_ip.addr) {
                 uint8_t* tcp_base = buf.data() + IPH_HL(ip) * 4;
                 uint16_t src_port = *(uint16_t*)tcp_base;
                 uint16_t dst_port = *(uint16_t*)(tcp_base + 2);
                 
                 if (src_port == ::htons(g_config.lwip_listen_port)) {
                     NatEntry target = NatTable::instance().get(::ntohs(dst_port));
                     
                     if (target.original_dst_ip != 0) {
                         ip->src.addr = target.original_dst_ip;
                         *(uint16_t*)tcp_base = target.original_dst_port;
                         
                         IPH_CHKSUM_SET(ip, 0);
                         IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
                         
                         uint16_t ip_len = ::ntohs(IPH_LEN(ip));
                         int tcp_len = ip_len - IPH_HL(ip) * 4;
                         recalculate_tcp_checksum(ip, tcp_base, tcp_len);
                     }
                 }
             }
        }
    }

    // The packet from LwIP is going out. We use the stored address from the
    // incoming packet and flip its direction.
    WINDIVERT_ADDRESS send_addr = g_last_addr;
    send_addr.Direction = (g_last_addr.Direction == WINDIVERT_DIRECTION_OUTBOUND) ? 
                           WINDIVERT_DIRECTION_INBOUND : 
                           WINDIVERT_DIRECTION_OUTBOUND;
    
    g_windivert_driver->send((const char*)buf.data(), buf.size(), &send_addr);
    return ERR_OK;
}

err_t windivert_netif_output(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr) {
    return netif->linkoutput(netif, p);
}

// --- Reassembled UDP Handling ---
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
                
                // Check if it's local traffic that should be bypassed
                uint16_t sp_h = ::ntohs(src_port);
                uint16_t dp_h = ::ntohs(dst_port);
                
                ip4_addr_t lwip_ip;
                ip4addr_aton("192.168.137.1", &lwip_ip);
                bool is_local = (sp_h == 53 || dp_h == 53 || ip->dest.addr == lwip_ip.addr);

                if (!is_local) {
                    uint8_t* payload = udp_ptr + 8;
                    int pay_len = len - (IPH_HL(ip) * 4 + 8);
                    handle_udp_packet(ip->src.addr, ip->dest.addr, src_port, dst_port, payload, pay_len);
                }
            }
        }
        pbuf_free(p);
        return 1; // Consumed
    }
    return 0;
}

err_t netif_init_cb(struct netif* netif) {
    netif->linkoutput = windivert_linkoutput;
    netif->output = windivert_netif_output;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;
    netif->hwaddr_len = 0; // No MAC address 

    // Register a raw PCB to catch reassembled UDP fragments
    struct raw_pcb* pcb = raw_new(IP_PROTO_UDP);
    if (pcb) {
        raw_bind(pcb, IP_ADDR_ANY);
        raw_recv(pcb, lwip_udp_raw_recv, NULL);
    }

    return ERR_OK;
}

void process_ip_packet(const char* buf_const, int len, const void* addr) {
    if (len < 20) return;

    // We need to modify the buffer for NAT, so we make a copy.
    char buf[WINDIVERT_MTU];
    memcpy(buf, buf_const, len);
    
    // Store the address for the reply
    g_last_addr = *(static_cast<const WINDIVERT_ADDRESS*>(addr));

    struct ip_hdr* ip = (struct ip_hdr*)buf;
    if (IPH_V(ip) == 4) {
        if (ntohs(IPH_LEN(ip)) > len) return;

        if (IPH_PROTO(ip) == IP_PROTO_UDP) {
            uint16_t frag_off = ::ntohs(IPH_OFFSET(ip));
            bool is_fragment = (frag_off & (IP_OFFMASK | IP_MF)) != 0;

            if (!is_fragment) {
                uint8_t* udp_ptr = (uint8_t*)buf + IPH_HL(ip) * 4;
                if ((char*)udp_ptr + 8 > buf + len) return; // Bounds check
                
                uint16_t src_port = *(uint16_t*)(udp_ptr + 0);
                uint16_t dst_port = *(uint16_t*)(udp_ptr + 2);

                // Let all UDP traffic pass to LwIP stack, which will use raw_recv to handle it.
                // This simplifies logic here and centralizes UDP handling in lwip_udp_raw_recv.
            }
        }

        // All traffic is from clients, going to the internet.
        // TCP traffic needs to be redirected to the LwIP listening port.
        if (IPH_PROTO(ip) == IP_PROTO_TCP) {
            uint8_t* tcp_base = (uint8_t*)buf + IPH_HL(ip) * 4;
            uint16_t src_port = *(uint16_t*)(tcp_base); 
            uint16_t dst_port = *(uint16_t*)(tcp_base + 2);
            uint32_t dst_ip = ip->dest.addr;

            NatTable::instance().set(::ntohs(src_port), dst_ip, dst_port);

            ip4_addr_t lwip_ip;
            ip4addr_aton("192.168.137.1", &lwip_ip);
            ip->dest.addr = lwip_ip.addr;

            *(uint16_t*)(tcp_base + 2) = ::htons(g_config.lwip_listen_port);

            IPH_CHKSUM_SET(ip, 0);
            IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
            
            // LwIP is configured to ignore TCP checksums (CHECKSUM_CHECK_TCP 0)
        }

        // ICMP (Ping) processing
        if (IPH_PROTO(ip) == IP_PROTO_ICMP) {
            uint8_t* icmp_base = (uint8_t*)buf + IPH_HL(ip) * 4;
            if (icmp_base[0] == 8) { // Echo Request
                
                // If the ping is for our gateway, reply directly.
                ip4_addr_t lwip_ip;
                ip4addr_aton("192.168.137.1", &lwip_ip);
                if (ip->dest.addr == lwip_ip.addr) {
                    uint32_t tmp_ip = ip->src.addr;
                    ip->src.addr = ip->dest.addr;
                    ip->dest.addr = tmp_ip;
                    icmp_base[0] = 0; // Echo Reply
                    
                    IPH_CHKSUM_SET(ip, 0);
                    IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));

                    int ip_len = ::ntohs(IPH_LEN(ip));
                    int icmp_len = ip_len - IPH_HL(ip) * 4;
                    *(uint16_t*)(icmp_base + 2) = 0;
                    *(uint16_t*)(icmp_base + 2) = ip_chksum_simple(icmp_base, icmp_len);

                    if (g_windivert_driver) {
                        WINDIVERT_ADDRESS send_addr = g_last_addr;
                        send_addr.Direction = WINDIVERT_DIRECTION_INBOUND;
                        g_windivert_driver->send((const char*)buf, len, &send_addr);
                    }
                    return; // Handled
                }
            }
        }
        
        // For all other traffic (UDP, and TCP to be processed by LwIP)
        struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        if (p) {
            pbuf_take(p, buf, len);
            if (g_netif.input(p, &g_netif) != ERR_OK) {
                pbuf_free(p);
            }
        }
    }
}