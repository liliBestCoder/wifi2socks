#include "lwip_handler.h"
#include "app_config.h"
#include "tun_driver.h"
#include "nat_table.h"
#include "proxy_udp.h"
#include <vector>
#include <iostream>
#include <stdarg.h>

std::recursive_mutex g_lwip_mtx;
struct netif g_netif;
uint8_t HOST_MAC[6] = { 0 }; 
bool g_host_mac_known = false;

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
    if (len > 0) { sum += (uint16_t)(*(const uint8_t*)ptr << 8); }
    return sum;
}

// Helper to construct and send ICMP Port Unreachable (Type 3, Code 3)
// This tells the client (YouTube) immediately that UDP/QUIC is blocked, triggering fast fallback to TCP.
void send_icmp_port_unreachable(uint8_t* req_buf, int req_len) {
    if (req_len < 34) return; // Minimum size: Eth(14) + IP(20)

    struct ip_hdr* req_ip = (struct ip_hdr*)(req_buf + 14);
    int req_ip_hlen = IPH_HL(req_ip) * 4;
    
    // ICMP Payload: Original IP Header + first 8 bytes of Original Data (UDP Header)
    // Packet Structure: [Ethernet 14] [IP 20] [ICMP 8] [Orig IP Header] [Orig Data 8]
    int icmp_payload_len = req_ip_hlen + 8;
    int resp_len = 14 + 20 + 8 + icmp_payload_len;
    
    if (req_len < 14 + icmp_payload_len) return; // Safety check

    std::vector<uint8_t> resp(resp_len);
    uint8_t* ptr = resp.data();

    // 1. Ethernet Header (Swap MACs)
    memcpy(ptr, req_buf + 6, 6);      // Dst MAC = Req Src MAC
    memcpy(ptr + 6, req_buf, 6);      // Src MAC = Req Dst MAC
    *(uint16_t*)(ptr + 12) = ::htons(0x0800); // IPv4 type

    // 2. IP Header
    struct ip_hdr* resp_ip = (struct ip_hdr*)(ptr + 14);
    IPH_VHL_SET(resp_ip, 4, 5);
    IPH_TOS_SET(resp_ip, 0);
    IPH_LEN_SET(resp_ip, ::htons(resp_len - 14));
    IPH_ID_SET(resp_ip, ::htons(0x1337));
    IPH_OFFSET_SET(resp_ip, 0);
    IPH_TTL_SET(resp_ip, 64);
    IPH_PROTO_SET(resp_ip, IP_PROTO_ICMP);
    resp_ip->src.addr = req_ip->dest.addr; // From: The IP client tried to reach
    resp_ip->dest.addr = req_ip->src.addr; // To: The client
    IPH_CHKSUM_SET(resp_ip, 0);
    IPH_CHKSUM_SET(resp_ip, ip_chksum_simple(resp_ip, 20));

    // 3. ICMP Header
    uint8_t* icmp_base = ptr + 14 + 20;
    icmp_base[0] = 3; // Type: Destination Unreachable
    icmp_base[1] = 3; // Code: Port Unreachable
    *(uint16_t*)(icmp_base + 2) = 0; // Checksum placeholder
    *(uint32_t*)(icmp_base + 4) = 0; // Unused

    // 4. ICMP Payload (Original Packet)
    memcpy(icmp_base + 8, req_buf + 14, icmp_payload_len);

    // 5. Calculate ICMP Checksum
    // Checksum covers ICMP Header + Payload
    *(uint16_t*)(icmp_base + 2) = ip_chksum_simple(icmp_base, 8 + icmp_payload_len);

    // 6. Send back to TAP
    TunDriver::instance().send_async(resp.data(), (int)resp.size());
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

err_t tap_linkoutput(struct netif* netif, struct pbuf* p) {
    // Optimization: Use static buffer to avoid heap allocation per packet.
    // In TUN mode, p->payload points directly to the IP header.
    static std::vector<uint8_t> buf;
    buf.clear();
    buf.reserve(p->tot_len);

    for (struct pbuf* q = p; q != NULL; q = q->next) {
        buf.insert(buf.end(), (uint8_t*)q->payload, (uint8_t*)q->payload + q->len);
    }

    if (buf.size() >= 20) {
        struct ip_hdr* ip = (struct ip_hdr*)buf.data();
        if (IPH_V(ip) == 4 && IPH_PROTO(ip) == IP_PROTO_TCP) {
             if (ip->src.addr == ::inet_addr(g_config.tap_gateway.c_str())) {
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

    TunDriver::instance().send_async(buf.data(), (int)buf.size());
    return ERR_OK;
}

err_t netif_init_cb(struct netif* netif) {
    netif->linkoutput = tap_linkoutput;
    netif->output = ip4_output; // Use direct IP output instead of etharp_output
    netif->mtu = 1500;
    // Remove NETIF_FLAG_ETHARP
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;
    netif->hwaddr_len = 0; // No MAC address in TUN mode
    return ERR_OK;
}

void process_tap_frame(uint8_t* buf, int len) {
    if (len < 20) return; // Minimum IP header size

    struct ip_hdr* ip = (struct ip_hdr*)buf;
    if (IPH_V(ip) == 4) {
        if (IPH_PROTO(ip) == IP_PROTO_UDP) {
            uint8_t* udp_ptr = buf + IPH_HL(ip) * 4;
            uint16_t src_port = *(uint16_t*)(udp_ptr + 0);
            uint16_t dst_port = *(uint16_t*)(udp_ptr + 2);

            // Bypass proxy for DHCP (67/68) or local gateway (192.168.137.1) traffic
            uint16_t sp_h = ::ntohs(src_port);
            uint16_t dp_h = ::ntohs(dst_port);
            bool is_local = (sp_h == 67 || dp_h == 67 || sp_h == 68 || dp_h == 68 || ip->dest.addr == ::inet_addr("192.168.137.1"));

            if (!is_local) {
                uint8_t* payload = udp_ptr + 8;
                int pay_len = len - (IPH_HL(ip) * 4 + 8);
                if (pay_len >= 0) {
                    handle_udp_packet(ip->src.addr, ip->dest.addr, src_port, dst_port, payload, pay_len);
                }
                return; // Proxy handled, stop here
            }
            // If local, do NOT return, let it fall through to g_netif.input
        }

        if (IPH_PROTO(ip) == IP_PROTO_TCP) {
            uint8_t* tcp_base = buf + IPH_HL(ip) * 4;
            uint16_t src_port = *(uint16_t*)(tcp_base); 
            uint16_t dst_port = *(uint16_t*)(tcp_base + 2);
            uint32_t dst_ip = ip->dest.addr;

            NatTable::instance().set(::ntohs(src_port), dst_ip, dst_port);

            ip->dest.addr = ::inet_addr(g_config.tap_gateway.c_str());
            *(uint16_t*)(tcp_base + 2) = ::htons(g_config.lwip_listen_port);

            IPH_CHKSUM_SET(ip, 0);
            IPH_CHKSUM_SET(ip, ip_chksum_simple(ip, IPH_HL(ip) * 4));
            
            uint16_t ip_len = ::ntohs(IPH_LEN(ip));
            int tcp_len = ip_len - IPH_HL(ip) * 4;
            if (tcp_len > 0) {
                recalculate_tcp_checksum(ip, tcp_base, tcp_len);
            }
        }

        if (IPH_PROTO(ip) == IP_PROTO_ICMP) {
            if (ip->dest.addr != ::inet_addr(g_config.tap_gateway.c_str())) {
                uint8_t* icmp_base = buf + IPH_HL(ip) * 4;
                if (icmp_base[0] == 8) {
                    // Swap IP addresses
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

                    TunDriver::instance().send_async(buf, len);
                    return;
                }
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
