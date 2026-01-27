#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "ucb.h"
#include "ucb_utils.h"
#include "arp.h"
#include "utils.h"
#include <thread>
#include <set>
#include <mutex>
#include <iostream>
#include <string>

#define UDP_ADDR "192.168.21.5"

static std::mutex g_log_mtx;
template<typename... Args>
static void log_line(const char* fmt, Args... a) {
    std::lock_guard<std::mutex> lk(g_log_mtx);
    printf(fmt, a...);
    printf("\n");
    fflush(stdout);
}

// Helper to parse DNS name with compression support
static std::string parse_dns_name(const uint8_t* buf, int len, int& pos) {
    std::string name;
    int jumps = 0;
    int p = pos;
    
    while (p < len) {
        uint8_t c = buf[p];
        if (c == 0) {
            p++;
            if (jumps == 0) pos = p;
            return name;
        }
        if ((c & 0xC0) == 0xC0) { // Pointer
            if (p + 1 >= len) return "";
            if (jumps == 0) pos = p + 2;
            int offset = ((c & 0x3F) << 8) | buf[p + 1];
            p = offset;
            jumps++;
            if (jumps > 5) return ""; // Loop protection
        } else {
            if (p + 1 + c > len) return "";
            if (!name.empty()) name += ".";
            name.append((char*)buf + p + 1, c);
            p += 1 + c;
        }
    }
    return "";
}

/* 线程：把中继回包注回 TAP */
static void udp_relay_to_tap(HANDLE tap, Quad q, SOCKET udpSock) {
    uint8_t buf[2048];
    while (true) {
        int r = recvfrom(udpSock, (char*)buf, sizeof(buf), 0, nullptr, nullptr);
        if (r == 0) break;
        if (r < 0) {
            int err = WSAGetLastError();
            if (err == WSAEINTR || err == WSAEWOULDBLOCK) continue;
            break;
        }

        // SOCKS5 UDP Unpack
        if (r < 10) {
            printf("[UCB] Recv too small packet: %d bytes\n", r);
            continue; 
        }
        
        // Debug Log: Print header details
        // Header: RSV(2) FRAG(1) ATYP(1)
        printf("[UCB] Recv %d bytes. Header: %02X %02X %02X %02X\n", r, buf[0], buf[1], buf[2], buf[3]);

        int offset = 0;
        if (buf[0] != 0 || buf[1] != 0) {
             printf("[UCB] Bad RSV\n");
             continue; 
        }
        
        uint32_t src_ip = 0;
        uint16_t src_port = 0;
        
        if (buf[3] == 0x01) { // IPv4
            src_ip = *(uint32_t*)(buf + 4); // Net Order
            src_port = *(uint16_t*)(buf + 8); // Net Order
            offset = 10;
        } else {
            // For domain/IPv6, just ignore for now or implement later
            continue; 
        }

        uint8_t* payload = buf + offset;
        int payload_len = r - offset;

        // Log DNS Response
        if (ntohs(src_port) == 53 && payload_len > 12) {
             int pos = 12; // Skip Header
             std::string qname = parse_dns_name(payload, payload_len, pos);
             pos += 4; // Skip QTYPE, QCLASS
             
             uint16_t ancount = ntohs(*(uint16_t*)(payload + 6));
             if (!qname.empty()) {
                 std::string ips;
                 for (int i=0; i<ancount && pos < payload_len; ++i) {
                     parse_dns_name(payload, payload_len, pos); // Skip Name
                     if (pos + 10 > payload_len) break;
                     uint16_t type = ntohs(*(uint16_t*)(payload + pos));
                     uint16_t data_len = ntohs(*(uint16_t*)(payload + pos + 8));
                     pos += 10;
                     if (type == 1 && data_len == 4 && pos + 4 <= payload_len) { // A Record
                         uint32_t ip_val = *(uint32_t*)(payload + pos);
                         char ip_str[INET_ADDRSTRLEN];
                         inet_ntop(AF_INET, &ip_val, ip_str, sizeof(ip_str));
                         ips += std::string(ip_str) + " ";
                     }
                     pos += data_len;
                 }
                 if (!ips.empty()) {
                    printf("[DNS-RES] %s -> %s\n", qname.c_str(), ips.c_str());
                 }
             }
        }

        uint8_t frame[2048];
        if (14 + 20 + 8 + payload_len > 2048) continue;

        memcpy(frame, TAP_MAC, 6);      
        memcpy(frame + 6, TAP_MAC, 6);   \
        *(uint16_t*)(frame + 12) = htons(0x0800);

        uint8_t* ip = frame + 14;
        uint8_t* udp = ip + 20;
        
        memset(ip, 0, 20);
        ip[0] = 0x45;
        *(uint16_t*)(ip + 2) = htons(20 + 8 + payload_len);
        ip[8] = 64;
        ip[9] = 17; // UDP
        *(uint32_t*)(ip + 12) = src_ip;   // Src IP (From SOCKS)
        *(uint32_t*)(ip + 16) = q.saddr;  // Dst IP (Client)
        *(uint16_t*)(ip + 10) = checksum(ip, 20);

        *(uint16_t*)(udp + 0) = src_port; // Src Port
        *(uint16_t*)(udp + 2) = q.sport;   // Dst Port (Quad is Net Order)
        *(uint16_t*)(udp + 4) = htons(8 + payload_len);
        *(uint16_t*)(udp + 6) = 0; 
        
        memcpy(udp + 8, payload, payload_len);
        
        *(uint16_t*)(udp + 6) = udp_cksum(src_ip, q.saddr, udp, 8 + payload_len);

        platform_send_frame(tap, frame, 14 + 20 + 8 + payload_len);
    }
    closesocket(udpSock);
}

void process_udp_packet(UCB& ucb, const Packet& pkt, HANDLE tap) {
    if (ucb.udpSock == INVALID_SOCKET) {
        SOCKET udp = socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = inet_addr(UDP_ADDR); 
        local.sin_port = htons(0);
        
        bind(udp, (sockaddr*)&local, sizeof(local));
        ucb.udpSock = udp;

        std::thread(udp_relay_to_tap, tap, ucb.quad, udp).detach();
    }

    // Original Dst Port (Packet Quad is Net Order)
    uint16_t dport = pkt.quad.dport;
    uint32_t daddr = pkt.quad.daddr;

    // DNS Hijack: Redirect all DNS queries (port 53) to 8.8.8.8
    if (ntohs(dport) == 53) {
        daddr = inet_addr("8.8.8.8");
        
        if (pkt.payload.size() > 12) {
            int pos = 12;
            std::string qname = parse_dns_name(pkt.payload.data(), pkt.payload.size(), pos);
            printf("[DNS-REQ] Query: %s\n", qname.c_str());
        }
    }

    std::vector<uint8_t> buf;
    buf.push_back(0x00); buf.push_back(0x00); 
    buf.push_back(0x00); 
    buf.push_back(0x01); 
    
    // Target IP
    uint8_t* pIP = (uint8_t*)&daddr;
    buf.push_back(pIP[0]);
    buf.push_back(pIP[1]);
    buf.push_back(pIP[2]);
    buf.push_back(pIP[3]);
    
    // Original Dst Port (Packet Quad is Net Order)
    // uint16_t dport = pkt.quad.dport; // Already defined above
    uint8_t* pPort = (uint8_t*)&dport;
    buf.push_back(pPort[0]);
    buf.push_back(pPort[1]);
    
    buf.insert(buf.end(), pkt.payload.begin(), pkt.payload.end());

    sockaddr_in to = { 0 };
    to.sin_family = AF_INET;
    to.sin_port = htons(SOCKS_SERVER_PORT);
    to.sin_addr.s_addr = inet_addr(SOCKS_SERVER_IP);
    
    sendto(ucb.udpSock, (char*)buf.data(), (int)buf.size(), 0, (sockaddr*)&to, sizeof(to));
}