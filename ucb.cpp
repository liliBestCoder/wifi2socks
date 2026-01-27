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
#include <vector>

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
            if (p + 1 >= len) return "<err-ptr-len>";
            int offset = ((c & 0x3F) << 8) | buf[p + 1];
            if (jumps == 0) pos = p + 2;
            p = offset;
            jumps++;
            if (jumps > 10) return "<err-loop>"; // Loop protection
        } else { // Label
            if (p + 1 + c > len) return "<err-label-len>";
            if (!name.empty()) name += ".";
            name.append((char*)buf + p + 1, c);
            p += 1 + c;
        }
    }
    return "<err-overflow>";
}

// Helper: recv N bytes strictly
static bool recv_all(SOCKET s, uint8_t* buf, int len) {
    int total = 0;
    while (total < len) {
        int r = recv(s, (char*)buf + total, len - total, 0);
        if (r <= 0) return false;
        total += r;
    }
    return true;
}

static void ucb_worker_loop(UCB* ucb, HANDLE tap) {
    // 0. Prepare UDP Socket FIRST to get the port
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp == INVALID_SOCKET) return;

    sockaddr_in local {};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY); 
    local.sin_port = htons(0); // Let OS pick port
    if (bind(udp, (sockaddr*)&local, sizeof(local)) != 0) {
        printf("[UCB] UDP Bind failed\n");
        closesocket(udp);
        return;
    }

    // Get the assigned port
    sockaddr_in my_addr;
    int my_addr_len = sizeof(my_addr);
    getsockname(udp, (sockaddr*)&my_addr, &my_addr_len);
    // Force IP to 127.0.0.1 because we are localhost
    my_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // 1. Establish TCP Control Connection
    SOCKET tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp == INVALID_SOCKET) {
        closesocket(udp);
        return;
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(SOCKS_SERVER_IP);
    addr.sin_port = htons(SOCKS_SERVER_PORT);

    printf("[UCB] Connecting TCP to SOCKS5 %s:%d for UDP ASSOCIATE (My Port: %d)...\n", 
        SOCKS_SERVER_IP, SOCKS_SERVER_PORT, ntohs(my_addr.sin_port));
        
    if (connect(tcp, (sockaddr*)&addr, sizeof(addr)) != 0) {
        printf("[UCB] TCP connect failed: %d\n", WSAGetLastError());
        closesocket(tcp);
        closesocket(udp);
        return;
    }

    // 2. Auth
    uint8_t buf[4096]; 
    uint8_t handshake[] = { 0x05, 0x01, 0x00 };
    send(tcp, (char*)handshake, 3, 0);
    if (!recv_all(tcp, buf, 2) || buf[1] != 0x00) {
        printf("[UCB] Auth failed\n");
        closesocket(tcp); closesocket(udp); return;
    }

    // 3. UDP ASSOCIATE Request
    // Tell proxy OUR IP and PORT
    uint8_t req[10];
    req[0] = 0x05; req[1] = 0x03; req[2] = 0x00; req[3] = 0x01; // IPv4
    *(uint32_t*)(req + 4) = my_addr.sin_addr.s_addr;
    *(uint16_t*)(req + 8) = my_addr.sin_port;
    send(tcp, (char*)req, 10, 0);

    // 4. Read Reply
    if (!recv_all(tcp, buf, 4)) { closesocket(tcp); closesocket(udp); return; }
    if (buf[1] != 0x00) {
        printf("[UCB] UDP ASSOCIATE rejected: %02x\n", buf[1]);
        closesocket(tcp); closesocket(udp); return;
    }
    
    // Parse Relay Address
    uint32_t relay_ip = 0;
    uint16_t relay_port = 0;
    uint8_t atyp = buf[3];
    
    if (atyp == 0x01) { // IPv4
        if (!recv_all(tcp, buf, 4 + 2)) { closesocket(tcp); closesocket(udp); return; }
        relay_ip = *(uint32_t*)buf;
        relay_port = *(uint16_t*)(buf + 4);
    } else if (atyp == 0x03) { // Domain
        if (!recv_all(tcp, buf, 1)) { closesocket(tcp); closesocket(udp); return; }
        int len = buf[0];
        if (!recv_all(tcp, buf, len + 2)) { closesocket(tcp); closesocket(udp); return; }
        relay_ip = inet_addr(SOCKS_SERVER_IP); 
        relay_port = *(uint16_t*)(buf + len);
    } else {
        printf("[UCB] Unsupported ATYP in UDP ASSOCIATE: %02x\n", atyp);
        closesocket(tcp); closesocket(udp); return;
    }

    if (relay_ip == 0) relay_ip = inet_addr(SOCKS_SERVER_IP);

    printf("[UCB] UDP ASSOCIATE Success. Relay: %u.%u.%u.%u:%u\n", 
        relay_ip & 0xFF, (relay_ip>>8)&0xFF, (relay_ip>>16)&0xFF, (relay_ip>>24)&0xFF, ntohs(relay_port));

    ucb->relay_ip = relay_ip;
    ucb->relay_port = relay_port;
    ucb->tcpSock = tcp;
    ucb->udpSock = udp;
    ucb->ready_to_send = true;

    // 6. Main Loop
    while (!ucb->stop_thread) {
        fd_set rd_set;
        FD_ZERO(&rd_set);
        FD_SET(tcp, &rd_set);
        FD_SET(udp, &rd_set);

        timeval tv = { 0, 5000 }; 
        int n = select(0, &rd_set, NULL, NULL, &tv);

        if (n < 0) break; 

        // Check TCP
        if (FD_ISSET(tcp, &rd_set)) {
            int r = recv(tcp, (char*)buf, 1, 0); 
            if (r <= 0) {
                printf("[UCB] TCP Control closed.\n");
                break;
            }
        }

        // Check UDP (Incoming data from Proxy)
        if (FD_ISSET(udp, &rd_set)) {
            int r = recvfrom(udp, (char*)buf, 4096, 0, NULL, NULL);
            if (r > 0) { 
                // UNCOMMENTED DEBUG LOG
                // printf("[UCB-DEBUG] Recv UDP %d bytes. Header: %02X %02X %02X %02X\n", r, buf[0], buf[1], buf[2], buf[3]);

                if (r < 10) continue; 
                
                int offset = 0;
                if (buf[0] != 0 || buf[1] != 0) continue; 
                
                uint32_t src_ip = 0;
                uint16_t src_port = 0;
                uint8_t atyp = buf[3];
                
                if (atyp == 0x01) { // IPv4
                    src_ip = *(uint32_t*)(buf + 4); 
                    src_port = *(uint16_t*)(buf + 8); 
                    offset = 10;
                } else if (atyp == 0x04) { // IPv6
                    src_port = *(uint16_t*)(buf + 20); 
                    offset = 22;
                } else {
                    continue; 
                }

                uint8_t* payload = buf + offset;
                int payload_len = r - offset;

                if (offset > 0 && payload_len > 12) {
                    // Enhanced DNS Parsing and Logging
                    if (ntohs(src_port) == 53) {
                         int pos = 12; // Skip Header
                         std::string qname = parse_dns_name(payload, payload_len, pos);
                         
                         uint16_t ancount = ntohs(*(uint16_t*)(payload + 6));
                         // Skip Questions
                         pos = 12; 
                         uint16_t qdcount = ntohs(*(uint16_t*)(payload + 4));
                         for(int k=0; k<qdcount; ++k) {
                             parse_dns_name(payload, payload_len, pos);
                             pos += 4; 
                         }

                         std::string info = "";
                         for (int i=0; i<ancount && pos < payload_len; ++i) {
                             parse_dns_name(payload, payload_len, pos); 
                             if (pos + 10 > payload_len) break;
                             
                             uint16_t type = ntohs(*(uint16_t*)(payload + pos));
                             uint16_t data_len = ntohs(*(uint16_t*)(payload + pos + 8));
                             pos += 10;
                             
                             if (pos + data_len > payload_len) break;

                             if (type == 1 && data_len == 4) { // A
                                 char ip_str[INET_ADDRSTRLEN];
                                 inet_ntop(AF_INET, payload + pos, ip_str, sizeof(ip_str));
                                 info += "A:" + std::string(ip_str) + " ";
                             } else if (type == 5) { // CNAME
                                 info += "CNAME ";
                             } else if (type == 28) { // AAAA
                                 info += "AAAA ";
                             }
                             pos += data_len;
                         }
                         
                         if (info.empty()) info = "No Records/Parse Error";
                         printf("[DNS-RES] %s -> %s (via UDP Relay)\n", qname.c_str(), info.c_str());
                    }

                    // Send to TAP
                    uint8_t frame[2048];
                    memcpy(frame, TAP_MAC, 6);      
                    memcpy(frame + 6, TAP_MAC, 6);   
                    *(uint16_t*)(frame + 12) = htons(0x0800);

                    uint8_t* ip = frame + 14;
                    uint8_t* udp_hdr = ip + 20;
                    
                    memset(ip, 0, 20);
                    ip[0] = 0x45;
                    *(uint16_t*)(ip + 2) = htons(20 + 8 + payload_len);
                    ip[8] = 64; ip[9] = 17; // UDP
                    
                    *(uint32_t*)(ip + 12) = ucb->quad.daddr;   
                    *(uint32_t*)(ip + 16) = ucb->quad.saddr;  
                    *(uint16_t*)(ip + 10) = checksum(ip, 20);

                    *(uint16_t*)(udp_hdr + 0) = src_port; 
                    *(uint16_t*)(udp_hdr + 2) = ucb->quad.sport;   
                    *(uint16_t*)(udp_hdr + 4) = htons(8 + payload_len);
                    *(uint16_t*)(udp_hdr + 6) = 0; 
                    
                    memcpy(udp_hdr + 8, payload, payload_len);
                    *(uint16_t*)(udp_hdr + 6) = udp_cksum(ucb->quad.daddr, ucb->quad.saddr, udp_hdr, 8 + payload_len);

                    platform_send_frame(tap, frame, 14 + 20 + 8 + payload_len);
                }
            }
        }

        // Send Data (From TAP to Proxy)
        {
            std::lock_guard<std::mutex> lk(ucb->mtx);
            while (!ucb->send_queue.empty()) {
                Packet pkt = ucb->send_queue.front();
                ucb->send_queue.pop_front();
                
                std::vector<uint8_t> sbuf;
                sbuf.push_back(0); sbuf.push_back(0); // RSV
                sbuf.push_back(0); // FRAG
                sbuf.push_back(1); // ATYP IPv4
                
                uint32_t target_ip = pkt.quad.daddr;
                if (ntohs(pkt.quad.dport) == 53) {
                    target_ip = inet_addr("8.8.8.8");
                    if (pkt.payload.size() > 12) {
                        int pos = 12;
                        std::string qname = parse_dns_name(pkt.payload.data(), (int)pkt.payload.size(), pos);
                        printf("[DNS-REQ] Query: %s (Hijacking to 8.8.8.8)\n", qname.c_str());
                    }
                }
                
                uint8_t* pIP = (uint8_t*)&target_ip;
                sbuf.push_back(pIP[0]); sbuf.push_back(pIP[1]); sbuf.push_back(pIP[2]); sbuf.push_back(pIP[3]);
                
                uint16_t dport_val = pkt.quad.dport;
                uint8_t* pPort = (uint8_t*)&dport_val;
                sbuf.push_back(pPort[0]); sbuf.push_back(pPort[1]);
                
                sbuf.insert(sbuf.end(), pkt.payload.begin(), pkt.payload.end());
                
                sockaddr_in relay_addr;
                relay_addr.sin_family = AF_INET;
                relay_addr.sin_addr.s_addr = ucb->relay_ip;
                relay_addr.sin_port = ucb->relay_port; 
                
                sendto(udp, (char*)sbuf.data(), (int)sbuf.size(), 0, (sockaddr*)&relay_addr, sizeof(relay_addr));
            }
        }
    }

    closesocket(tcp);
    closesocket(udp);
    ucb->tcpSock = INVALID_SOCKET;
    ucb->udpSock = INVALID_SOCKET;
}

UCB::UCB(const Quad& q) : quad(q), tcpSock(INVALID_SOCKET), udpSock(INVALID_SOCKET), 
    stop_thread(false), ready_to_send(false), is_running(false) {}

UCB::~UCB() {
    stop_thread = true;
    if (worker_th.joinable()) worker_th.join();
}

void process_udp_packet(UCB& ucb, const Packet& pkt, HANDLE tap) {
    // 1. Push to Queue
    {
        std::lock_guard<std::mutex> lk(ucb.mtx);
        ucb.send_queue.push_back(pkt);
    }

    // 2. Start Thread if needed
    if (!ucb.is_running) {
        if (ucb.worker_th.joinable()) ucb.worker_th.join(); // Clean up old thread if any
        ucb.is_running = true;
        
        ucb.worker_th = std::thread([&ucb, tap]() {
            ucb_worker_loop(&ucb, tap);
            ucb.is_running = false; 
        });
    }
}