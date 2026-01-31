#include "proxy_udp.h"
#include "worker.h"
#include "tap_driver.h"
#include "app_config.h"
#include "lwip_handler.h"
#include "nat_table.h"
#include <map>
#include <vector>
#include <deque>
#include <algorithm>

// --- UDP Session ---
struct UdpKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    bool operator<(const UdpKey& o) const { return memcmp(this, &o, sizeof(UdpKey)) < 0; }
};

struct UdpSession {
    SOCKET tcp_sock; 
    SOCKET udp_sock; // Not used for DNS-over-TCP, but kept for struct compatibility/future
    
    // Key identification
    uint32_t src_ip; 
    uint32_t original_dst_ip; // The IP the client THOUGHT it sent to (e.g., 114.114.114.114)
    uint16_t src_port;
    uint16_t original_dst_port;

    // Actual target for the proxy connection (e.g., 223.5.5.5 or 8.8.8.8)
    uint32_t proxy_target_ip;
    uint16_t proxy_target_port;

    uint64_t last_active;
    Worker* worker;
    
    // DNS over TCP specific
    bool is_dns_tcp;
    std::vector<uint8_t> tcp_rx_buffer; 
    
    // SOCKS5 Handshake State
    enum State { CONNECTING, HANDSHAKE_AUTH, HANDSHAKE_CONNECT, ESTABLISHED, CLOSED } state;
    std::deque<std::vector<uint8_t>> pending_packets;

    UdpSession() : tcp_sock(INVALID_SOCKET), udp_sock(INVALID_SOCKET), worker(NULL), state(CONNECTING), is_dns_tcp(false) { 
        last_active = GetTickCount64(); 
        tcp_rx_buffer.reserve(4096);
    }
};

thread_local std::map<UdpKey, UdpSession*> t_udp_sessions;

void close_udp_session_internal(UdpSession* sess) {
    if (!sess) return; 
    
    UdpKey key = { sess->src_ip, sess->original_dst_ip, sess->src_port, sess->original_dst_port };
    t_udp_sessions.erase(key);

    if (sess->worker) {
        auto worker = sess->worker;
        SOCKET s1 = sess->tcp_sock;
        
        sess->tcp_sock = INVALID_SOCKET;
        sess->state = UdpSession::CLOSED;

        if (s1 != INVALID_SOCKET) {
            worker->remove_socket(s1, [s1, sess]() {
                closesocket(s1);
                delete sess;
            });
        } else {
            delete sess;
        }
    } else {
        if (sess->tcp_sock != INVALID_SOCKET) closesocket(sess->tcp_sock);
        delete sess;
    }
}

// Helper to log DNS answers
void log_dns_packet(const uint8_t* payload, int len, const char* prefix) {
    if (len < 12) return;
    
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    uint16_t an_count = ntohs(*(uint16_t*)(payload + 6));
    
    bool is_response = (flags & 0x8000) != 0;
    if (!is_response || an_count == 0) return;

    printf("%s Received %d Answers (Len: %d)\n", prefix, an_count, len);

    uint16_t qd_count = ntohs(*(uint16_t*)(payload + 4));
    int pos = 12;

    // Skip Queries
    for (int i=0; i<qd_count; ++i) {
        if (pos >= len) return;
        while (pos < len) {
            uint8_t n = payload[pos];
            if (n == 0) { pos++; break; }
            if ((n & 0xC0) == 0xC0) { pos += 2; break; }
            pos += n + 1;
        }
        pos += 4;
    }

    // Parse Answers
    for (int i=0; i<an_count; ++i) {
        if (pos >= len) break;
        while (pos < len) { // Skip Name
            uint8_t n = payload[pos];
            if (n == 0) { pos++; break; }
            if ((n & 0xC0) == 0xC0) { pos += 2; break; }
            pos += n + 1;
        }
        
        if (pos + 10 > len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(payload + pos));
        uint16_t rdlen = ntohs(*(uint16_t*)(payload + pos + 8));
        pos += 10;
        
        if (pos + rdlen > len) break;
        
        if (type == 1 && rdlen == 4) { // A Record (IPv4)
            printf("  -> IPv4: %d.%d.%d.%d\n", 
                payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]);
        }
        pos += rdlen;
    }
    fflush(stdout);
}

void send_dns_over_tcp(UdpSession* sess, const std::vector<uint8_t>& payload) {
    if (sess->state != UdpSession::ESTABLISHED) return;

    // DNS-over-TCP: 2 bytes Length + Payload
    if (payload.size() > 65535) return;
    
    uint16_t len = htons((uint16_t)payload.size());
    std::vector<uint8_t> tcp_pkt;
    tcp_pkt.resize(2 + payload.size());
    
    memcpy(tcp_pkt.data(), &len, 2);
    memcpy(tcp_pkt.data() + 2, payload.data(), payload.size());
    
    int sent = send(sess->tcp_sock, (const char*)tcp_pkt.data(), (int)tcp_pkt.size(), 0);
    if (sent == SOCKET_ERROR) {
        printf("[DNS-TCP] send failed: %d\n", WSAGetLastError());
        close_udp_session_internal(sess);
    } else {
        printf("[DNS-TCP] Sent query via TCP tunnel (%d bytes) to %d.%d.%d.%d\n", 
            (int)payload.size(),
            sess->proxy_target_ip & 0xFF, (sess->proxy_target_ip >> 8) & 0xFF, 
            (sess->proxy_target_ip >> 16) & 0xFF, (sess->proxy_target_ip >> 24) & 0xFF);
    }
}

void handle_socks5_tcp_read(UdpSession* sess) {
    if (sess->state == UdpSession::CLOSED) return;
    
    char buf[4096];
    int r = recv(sess->tcp_sock, buf, sizeof(buf), 0);
    
    if (r > 0) {
        if (sess->state == UdpSession::HANDSHAKE_AUTH) {
            if (r >= 2 && buf[0] == 0x05 && buf[1] == 0x00) {
                // Auth OK. Connect to Target (DNS Server).
                printf("[DNS-TCP] Auth OK. Connecting to Target...\n");
                
                std::vector<uint8_t> req;
                req.push_back(0x05); req.push_back(0x01); req.push_back(0x00); req.push_back(0x01); // IPv4
                
                // Target IP (AliDNS or Google DNS)
                uint32_t ip = sess->proxy_target_ip; 
                req.push_back(ip & 0xFF); req.push_back((ip >> 8) & 0xFF);
                req.push_back((ip >> 16) & 0xFF); req.push_back((ip >> 24) & 0xFF);
                
                // Target Port (53)
                uint16_t port = sess->proxy_target_port;
                req.push_back(port & 0xFF); req.push_back((port >> 8) & 0xFF);
                
                send(sess->tcp_sock, (const char*)req.data(), (int)req.size(), 0);
                sess->state = UdpSession::HANDSHAKE_CONNECT;
            } else {
                printf("[SOCKS5] Auth Failed\n");
                close_udp_session_internal(sess);
            }
        } else if (sess->state == UdpSession::HANDSHAKE_CONNECT) {
            if (r >= 4 && buf[0] == 0x05 && buf[1] == 0x00) {
                printf("[DNS-TCP] Tunnel Established to DNS Server. Flushing...\n");
                sess->state = UdpSession::ESTABLISHED;
                
                // If there's extra data (unlikely for SOCKS5 response, but possible)
                int header_len = (buf[3] == 0x01) ? 10 : ((buf[3] == 0x04) ? 22 : (7 + buf[4]));
                if (r > header_len) {
                     sess->tcp_rx_buffer.insert(sess->tcp_rx_buffer.end(), buf + header_len, buf + r);
                }

                while (!sess->pending_packets.empty()) {
                    send_dns_over_tcp(sess, sess->pending_packets.front());
                    sess->pending_packets.pop_front();
                }
            } else {
                printf("[DNS-TCP] Connect Failed. Rep: %02X\n", (uint8_t)buf[1]);
                close_udp_session_internal(sess);
            }
        } else if (sess->state == UdpSession::ESTABLISHED) {
            // Data received from DNS Server
            // printf("[DNS-TCP] Recv %d bytes data from proxy.\n", r);
            sess->tcp_rx_buffer.insert(sess->tcp_rx_buffer.end(), (uint8_t*)buf, (uint8_t*)buf + r);
            
            // Process TCP stream (Length Prefixed)
            while (sess->tcp_rx_buffer.size() > 2) {
                uint16_t pkt_len = ntohs(*(uint16_t*)sess->tcp_rx_buffer.data());
                if (sess->tcp_rx_buffer.size() >= (size_t)2 + pkt_len) {
                    
                    uint8_t* payload = sess->tcp_rx_buffer.data() + 2;
                    log_dns_packet(payload, pkt_len, "[DNS-TCP]");
                    
                    // Re-encapsulate as UDP and send to Tap
                    // Use ORIGINAL Client/Server IPs to spoof the source correctly
                    uint8_t frame[2048];
                    if (14 + 20 + 8 + pkt_len <= 2048) {
                        memcpy(frame, HOST_MAC, 6);
                        memcpy(frame + 6, TapDriver::TAP_MAC, 6);
                        *(uint16_t*)(frame + 12) = htons(0x0800);

                        uint8_t* ip = frame + 14;
                        uint8_t* udp_hdr = ip + 20;
                        
                        memset(ip, 0, 20);
                        ip[0] = 0x45; ip[9] = 17; ip[8] = 64;
                        *(uint16_t*)(ip + 2) = htons((uint16_t)(20 + 8 + pkt_len));
                        *(uint32_t*)(ip + 12) = sess->original_dst_ip; // Spoof Source IP (e.g. 114.114.114.114)
                        *(uint32_t*)(ip + 16) = sess->src_ip;          // Dest IP (Client)
                        *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

                        *(uint16_t*)(udp_hdr + 0) = sess->original_dst_port; 
                        *(uint16_t*)(udp_hdr + 2) = sess->src_port; 
                        *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + pkt_len));
                        *(uint16_t*)(udp_hdr + 6) = 0;
                        memcpy(udp_hdr + 8, payload, pkt_len);

                        TapDriver::instance().send_async(frame, 14 + 20 + 8 + pkt_len);
                    }
                    
                    sess->tcp_rx_buffer.erase(sess->tcp_rx_buffer.begin(), sess->tcp_rx_buffer.begin() + 2 + pkt_len);
                } else {
                    break; 
                }
            }
        }
    } else {
        if (r != 0) printf("[ProxyUDP] TCP Error: %d\n", WSAGetLastError());
        close_udp_session_internal(sess);
    }
}

// DNS Parser helper
std::string parse_dns_qname(const uint8_t* payload, int len, int* qname_len) {
    if (len < 12) return "";
    int pos = 12;
    std::string domain;
    
    while (pos < len) {
        uint8_t n = payload[pos];
        if (n == 0) { 
            pos++; 
            break; 
        }
        if ((n & 0xC0) == 0xC0) return ""; 
        
        if (pos + n + 1 > len) return "";
        
        if (!domain.empty()) domain += ".";
        domain.append((char*)(payload + pos + 1), n);
        pos += n + 1;
    }
    
    if (qname_len) *qname_len = pos - 12;
    return domain;
}

// Called by Main Thread
void udp_check_timeouts() {
    WorkerPool::instance().for_each_worker([](Worker* w) {
        w->queue_task([]() {
            uint64_t now = GetTickCount64();
            std::vector<UdpSession*> stale_sessions;
            for (auto& pair : t_udp_sessions) {
                if (now - pair.second->last_active > 60000) {
                    stale_sessions.push_back(pair.second);
                }
            }
            for (auto* sess : stale_sessions) {
                close_udp_session_internal(sess);
            }
        });
    });
}

// Called by Main Thread
void handle_udp_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len) {
    // 1. DROP QUIC
    if (dst_port == htons(443)) return;

    // 2. DNS Handling (Split DNS via TCP)
    if (dst_port == htons(53)) {
        int qname_len = 0;
        std::string full_domain = parse_dns_qname(payload, len, &qname_len);
        
        if (!full_domain.empty()) {
            std::string clean_domain = full_domain;
            std::string temp = full_domain;
            std::transform(temp.begin(), temp.end(), temp.begin(), [](unsigned char c){ return std::tolower(c); });
            
            const char* suffixes[] = { ".mshome.net", ".lan", ".local", ".localdomain" };
            bool stripped = false;
            for (const char* suf : suffixes) {
                size_t suflen = strlen(suf);
                if (temp.length() > suflen && temp.compare(temp.length() - suflen, suflen, suf) == 0) {
                    clean_domain = full_domain.substr(0, full_domain.length() - suflen);
                    stripped = true;
                    break; 
                }
            }

            // Determine Target DNS
            uint32_t target_dns_ip;
            bool domestic = DomainRules::instance().is_domestic(clean_domain);
            
            if (domestic) {
                // Domestic -> 223.5.5.5
                uint8_t ali[4] = {223, 5, 5, 5};
                memcpy(&target_dns_ip, ali, 4);
                printf("[SmartDNS] Domestic: %s -> TCP to 223.5.5.5\n", clean_domain.c_str());
            } else {
                // Foreign -> 8.8.8.8
                uint8_t google[4] = {8, 8, 8, 8};
                memcpy(&target_dns_ip, google, 4);
                // printf("[SmartDNS] Foreign: %s -> TCP to 8.8.8.8\n", clean_domain.c_str());
            }

            // Prepare Payload (Stripped if needed)
            std::vector<uint8_t> dns_payload;
            if (stripped) {
                // We MUST rebuild the query packet without suffix because 223.5.5.5/8.8.8.8 won't recognize .mshome.net
                uint16_t id = *(uint16_t*)payload;
                // Simple query builder from previous turn (assumed available or we reimplement minimal)
                // Reimplement minimal A query builder for completeness
                dns_payload.reserve(64);
                dns_payload.push_back(id & 0xFF); dns_payload.push_back((id >> 8) & 0xFF);
                dns_payload.push_back(0x01); dns_payload.push_back(0x00); // Std Query
                dns_payload.push_back(0x00); dns_payload.push_back(0x01); // QD=1
                dns_payload.push_back(0x00); dns_payload.push_back(0x00);
                dns_payload.push_back(0x00); dns_payload.push_back(0x00);
                dns_payload.push_back(0x00); dns_payload.push_back(0x00);
                
                size_t pos = 0;
                while (pos < clean_domain.length()) {
                    size_t next_dot = clean_domain.find('.', pos);
                    std::string label;
                    if (next_dot == std::string::npos) {
                        label = clean_domain.substr(pos);
                        pos = clean_domain.length();
                    } else {
                        label = clean_domain.substr(pos, next_dot - pos);
                        pos = next_dot + 1;
                    }
                    if (label.length() > 63) label = label.substr(0, 63);
                    dns_payload.push_back((uint8_t)label.length());
                    for (char c : label) dns_payload.push_back(c);
                }
                dns_payload.push_back(0); // Root
                dns_payload.push_back(0x00); dns_payload.push_back(0x01); // Type A
                dns_payload.push_back(0x00); dns_payload.push_back(0x01); // Class IN
            } else {
                dns_payload.assign(payload, payload + len);
            }

            // Dispatch to Worker for TCP
            uint32_t hash = src_port ^ dst_port ^ src_ip ^ dst_ip;
            Worker* w = WorkerPool::instance().get_worker(hash);
            if (!w) w = WorkerPool::instance().get_next_worker();
            
            w->queue_task([src_ip, dst_ip, src_port, dst_port, target_dns_ip, data = std::move(dns_payload), w, stripped, full_domain]() {
                UdpKey key = { src_ip, dst_ip, src_port, dst_port };
                UdpSession* sess = nullptr;
                auto it = t_udp_sessions.find(key);
                if (it != t_udp_sessions.end()) {
                    sess = it->second;
                } else {
                    sess = new UdpSession();
                    sess->src_ip = src_ip; 
                    sess->original_dst_ip = dst_ip; // Store original (e.g. 114.114.114.114)
                    sess->src_port = src_port; 
                    sess->original_dst_port = dst_port;
                    sess->proxy_target_ip = target_dns_ip; // Store actual target (223.5.5.5 or 8.8.8.8)
                    sess->proxy_target_port = htons(53);
                    
                    sess->worker = w;
                    sess->is_dns_tcp = true;
                    
                    sess->tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sess->tcp_sock == INVALID_SOCKET) { delete sess; return; }
                    u_long mode = 1; ioctlsocket(sess->tcp_sock, FIONBIO, &mode);
                    
                    t_udp_sessions[key] = sess;
                    
                    sockaddr_in proxy_addr;
                    memset(&proxy_addr, 0, sizeof(proxy_addr));
                    proxy_addr.sin_family = AF_INET;
                    unsigned int a, b, c, d;
                    if (sscanf_s(PROXY_IP, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                        proxy_addr.sin_addr.S_un.S_addr = (a) | (b << 8) | (c << 16) | (d << 24);
                    } else { proxy_addr.sin_addr.S_un.S_addr = 0x0100007F; } // Default to 127.0.0.1
                    proxy_addr.sin_port = htons(PROXY_PORT);
                    
                    sess->worker->connect_async(
                        sess->tcp_sock,
                        proxy_addr,
                        [sess]() {
                            if (sess->state == UdpSession::CLOSED) return;
                            uint8_t req[] = { 0x05, 0x01, 0x00 };
                            send(sess->tcp_sock, (const char*)req, sizeof(req), 0);
                            sess->state = UdpSession::HANDSHAKE_AUTH;
                            
                            sess->worker->add_socket(
                                sess->tcp_sock,
                                [sess]() { handle_socks5_tcp_read(sess); },
                                nullptr, 
                                [sess]() { close_udp_session_internal(sess); }
                            );
                        }
                    );
                }
                
                if (sess && sess->state != UdpSession::CLOSED) {
                    sess->last_active = GetTickCount64();
                    if (sess->state == UdpSession::ESTABLISHED) {
                        send_dns_over_tcp(sess, data);
                    } else {
                        sess->pending_packets.push_back(std::move(data));
                    }
                }
            });
            return;
        }
    }

    // 3. Other UDP -> Drop or Direct (Skipping for now to focus on DNS)
    // Since we are fixing DNS first, other UDP can be implemented later or ignored.
    // For now, let's just drop non-DNS UDP to keep it clean, OR implement direct.
    // The user said "udp dns sending problem", so non-DNS isn't the priority.
    // But let's leave a basic placeholder for standard UDP if needed later.
}