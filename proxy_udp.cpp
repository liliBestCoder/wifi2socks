#include "proxy_udp.h"
#include "worker.h"
#include "tap_driver.h"
#include "app_config.h"
#include "lwip_handler.h"
#include "nat_table.h"
#include "geo_checker.h"
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
    SOCKET udp_sock; // Direct UDP socket
    
    // Key identification
    uint32_t src_ip; 
    uint32_t original_dst_ip; 
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
    
    // DNS Reconstruction State
    std::string original_domain_with_suffix; 
    std::string clean_domain; // For cache update
    
    // SOCKS5 Handshake State
    enum State { CONNECTING, HANDSHAKE_AUTH, HANDSHAKE_CONNECT, ESTABLISHED, CLOSED } state;
    std::deque<std::vector<uint8_t>> pending_packets;

    UdpSession() : tcp_sock(INVALID_SOCKET), udp_sock(INVALID_SOCKET), worker(NULL), state(CONNECTING), is_dns_tcp(false) { 
        last_active = GetTickCount64(); 
        tcp_rx_buffer.reserve(4096);
    }
};

std::string parse_dns_qname(const uint8_t* payload, int len, int* qname_len);

void parse_and_log_dns_response(const uint8_t* payload, int len, const char* mode) {
    if (len < 12) return;
    
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    uint16_t an_count = ntohs(*(uint16_t*)(payload + 6));
    
    if ((flags & 0x8000) && an_count > 0) { 
        uint16_t qd_count = ntohs(*(uint16_t*)(payload + 4));
        int pos = 12;
        
        std::string domain;
        if (qd_count > 0) {
            int qname_len = 0;
            domain = parse_dns_qname(payload, len, &qname_len);
            for(int i=0; i<qd_count; i++) {
                if (i > 0) { 
                     while(pos < len) {
                        uint8_t n = payload[pos];
                        if(n==0) { pos++; break; }
                        if((n&0xC0)==0xC0) { pos+=2; break; }
                        pos += n+1;
                    }
                } else {
                    if (!domain.empty() && qname_len > 0) pos += qname_len;
                    else {
                         while(pos < len) {
                            uint8_t n = payload[pos];
                            if(n==0) { pos++; break; }
                            if((n&0xC0)==0xC0) { pos+=2; break; }
                            pos += n+1;
                        }
                    }
                }
                pos += 4; 
            }
        }

        for(int i=0; i<an_count; i++) {
            if(pos >= len) break;
            while(pos < len) {
                uint8_t n = payload[pos];
                if(n==0) { pos++; break; }
                if((n&0xC0)==0xC0) { pos+=2; break; }
                pos += n+1;
            }
            if(pos+10 > len) break;
            
            uint16_t type = ntohs(*(uint16_t*)(payload+pos));
            uint32_t ttl = ntohl(*(uint32_t*)(payload+pos+4));
            uint16_t rdlen = ntohs(*(uint16_t*)(payload+pos+8));
            pos += 10;
            
            if (type == 1 && rdlen == 4 && pos + 4 <= len) { 
                uint32_t ip = *(uint32_t*)(payload + pos);
                LOG_INFO("[DNS] Resolved: %s -> %d.%d.%d.%d (TTL: %d) via %s\n", 
                    domain.empty() ? "(unknown)" : domain.c_str(),
                    ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, ttl, mode);
                if (!domain.empty()) DnsCache::instance().put(domain, ip, ttl);
                return; 
            }
            pos += rdlen;
        }
    }
}

thread_local std::map<UdpKey, UdpSession*> t_udp_sessions;

void close_udp_session_internal(UdpSession* sess) {
    if (!sess) return; 
    
    UdpKey key = { sess->src_ip, sess->original_dst_ip, sess->src_port, sess->original_dst_port };
    t_udp_sessions.erase(key);

    if (sess->worker) {
        auto worker = sess->worker;
        SOCKET s1 = sess->tcp_sock;
        SOCKET s2 = sess->udp_sock;
        
        sess->tcp_sock = INVALID_SOCKET;
        sess->udp_sock = INVALID_SOCKET;
        sess->state = UdpSession::CLOSED;

        worker->queue_task([worker, s1, s2, sess]() {
            if (s1 != INVALID_SOCKET) {
                worker->remove_socket(s1, [s1]() { closesocket(s1); });
            }
            if (s2 != INVALID_SOCKET) {
                worker->remove_socket(s2, [s2]() { closesocket(s2); });
            }
            delete sess;
        });
    } else {
        if (sess->tcp_sock != INVALID_SOCKET) closesocket(sess->tcp_sock);
        if (sess->udp_sock != INVALID_SOCKET) closesocket(sess->udp_sock);
        delete sess;
    }
}

void handle_udp_direct_read(UdpSession* sess) {
    if (sess->state == UdpSession::CLOSED) return;
    
    char buf[4096];
    sockaddr_in remote_addr;
    int addr_len = sizeof(remote_addr);
    int r = recvfrom(sess->udp_sock, buf, sizeof(buf), 0, (sockaddr*)&remote_addr, &addr_len);
    
    if (r > 0) {
        uint8_t frame[4096 + 100]; 
        if (14 + 20 + 8 + r > sizeof(frame)) return; 

        memcpy(frame, HOST_MAC, 6);
        memcpy(frame + 6, TapDriver::TAP_MAC, 6);
        *(uint16_t*)(frame + 12) = htons(0x0800);

        uint8_t* ip_hdr = frame + 14;
        uint8_t* udp_hdr = ip_hdr + 20;

        memset(ip_hdr, 0, 20);
        ip_hdr[0] = 0x45; 
        ip_hdr[8] = 64; 
        ip_hdr[9] = 17; 
        *(uint16_t*)(ip_hdr + 2) = htons((uint16_t)(20 + 8 + r));
        *(uint32_t*)(ip_hdr + 12) = sess->original_dst_ip; 
        *(uint32_t*)(ip_hdr + 16) = sess->src_ip;          
        *(uint16_t*)(ip_hdr + 10) = ip_chksum_simple(ip_hdr, 20);

        *(uint16_t*)(udp_hdr + 0) = sess->original_dst_port; 
        *(uint16_t*)(udp_hdr + 2) = sess->src_port;          
        *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + r));
        *(uint16_t*)(udp_hdr + 6) = 0; 
        
        memcpy(udp_hdr + 8, buf, r);

        // Try Log DNS Response for Direct UDP
        if (sess->original_dst_port == htons(53)) {
            parse_and_log_dns_response((const uint8_t*)buf, r, "Direct (UDP)");
        }

        sess->last_active = GetTickCount64();
        TapDriver::instance().send_async(frame, 14 + 20 + 8 + r);
    } else {
        // Can't read? 
    }
}

// Helper to build a DNS Response
void send_dns_response(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t id, const std::string& domain, uint32_t ip_addr) {
    std::vector<uint8_t> resp;
    resp.reserve(512);
    
    // Header
    resp.push_back(id & 0xFF); resp.push_back((id >> 8) & 0xFF);
    resp.push_back(0x81); resp.push_back(0x80); // Std Response
    resp.push_back(0x00); resp.push_back(0x01); // QD=1
    resp.push_back(0x00); resp.push_back(0x01); // AN=1
    resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x00); resp.push_back(0x00);
    
    // Question Section
    size_t pos = 0;
    while (pos < domain.length()) {
        size_t next_dot = domain.find('.', pos);
        std::string label;
        if (next_dot == std::string::npos) {
            label = domain.substr(pos);
            pos = domain.length();
        } else {
            label = domain.substr(pos, next_dot - pos);
            pos = next_dot + 1;
        }
        if (label.length() > 63) label = label.substr(0, 63); 
        resp.push_back((uint8_t)label.length());
        for (char c : label) resp.push_back(c);
    }
    resp.push_back(0); 
    
    resp.push_back(0x00); resp.push_back(0x01); // A
    resp.push_back(0x00); resp.push_back(0x01); // IN
    
    // Answer Section
    resp.push_back(0xC0); resp.push_back(0x0C); // Pointer to Name
    resp.push_back(0x00); resp.push_back(0x01); // A
    resp.push_back(0x00); resp.push_back(0x01); // IN
    resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x3C); // TTL 60
    resp.push_back(0x00); resp.push_back(0x04); // Len
    
    resp.push_back(ip_addr & 0xFF);
    resp.push_back((ip_addr >> 8) & 0xFF);
    resp.push_back((ip_addr >> 16) & 0xFF);
    resp.push_back((ip_addr >> 24) & 0xFF);
    
    // Send
    uint8_t frame[2048];
    if (14 + 20 + 8 + resp.size() > 2048) return;

    memcpy(frame, HOST_MAC, 6);
    memcpy(frame + 6, TapDriver::TAP_MAC, 6);
    *(uint16_t*)(frame + 12) = htons(0x0800);

    uint8_t* ip_hdr = frame + 14;
    uint8_t* udp_hdr = ip_hdr + 20;
    
    memset(ip_hdr, 0, 20);
    ip_hdr[0] = 0x45; ip_hdr[9] = 17; ip_hdr[8] = 64;
    *(uint16_t*)(ip_hdr + 2) = htons((uint16_t)(20 + 8 + resp.size()));
    *(uint32_t*)(ip_hdr + 12) = dst_ip; // Original Dst (DNS Server) acts as Src
    *(uint32_t*)(ip_hdr + 16) = src_ip; // Client IP
    *(uint16_t*)(ip_hdr + 10) = ip_chksum_simple(ip_hdr, 20);

    *(uint16_t*)(udp_hdr + 0) = dst_port; 
    *(uint16_t*)(udp_hdr + 2) = src_port; 
    *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + resp.size()));
    *(uint16_t*)(udp_hdr + 6) = 0;
    memcpy(udp_hdr + 8, resp.data(), resp.size());

    TapDriver::instance().send_async(frame, 14 + 20 + 8 + (int)resp.size());
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
        LOG_INFO("[DNS-TCP] send failed: %d\n", WSAGetLastError());
        close_udp_session_internal(sess);
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
                std::vector<uint8_t> req;
                req.push_back(0x05); req.push_back(0x01); req.push_back(0x00); req.push_back(0x01); // IPv4
                
                uint32_t ip = sess->proxy_target_ip; 
                req.push_back(ip & 0xFF); req.push_back((ip >> 8) & 0xFF);
                req.push_back((ip >> 16) & 0xFF); req.push_back((ip >> 24) & 0xFF);
                
                uint16_t port = sess->proxy_target_port;
                req.push_back(port & 0xFF); req.push_back((port >> 8) & 0xFF);
                
                send(sess->tcp_sock, (const char*)req.data(), (int)req.size(), 0);
                sess->state = UdpSession::HANDSHAKE_CONNECT;
            } else {
                close_udp_session_internal(sess);
            }
        } else if (sess->state == UdpSession::HANDSHAKE_CONNECT) {
            if (r >= 4 && buf[0] == 0x05 && buf[1] == 0x00) {
                // Connected
                sess->state = UdpSession::ESTABLISHED;
                
                int header_len = (buf[3] == 0x01) ? 10 : ((buf[3] == 0x04) ? 22 : (7 + buf[4]));
                if (r > header_len) {
                     sess->tcp_rx_buffer.insert(sess->tcp_rx_buffer.end(), buf + header_len, buf + r);
                }

                while (!sess->pending_packets.empty()) {
                    send_dns_over_tcp(sess, sess->pending_packets.front());
                    sess->pending_packets.pop_front();
                }
            } else {
                close_udp_session_internal(sess);
            }
        } else if (sess->state == UdpSession::ESTABLISHED) {
            sess->tcp_rx_buffer.insert(sess->tcp_rx_buffer.end(), (uint8_t*)buf, (uint8_t*)buf + r);
            
            while (sess->tcp_rx_buffer.size() > 2) {
                uint16_t pkt_len = ntohs(*(uint16_t*)sess->tcp_rx_buffer.data());
                if (sess->tcp_rx_buffer.size() >= (size_t)2 + pkt_len) {
                    
                    uint8_t* payload = sess->tcp_rx_buffer.data() + 2;
                    
                    // Parse Response to get IP and TTL
                    uint16_t id = *(uint16_t*)payload;
                    
                    // Parse and Log (updates cache internally)
                    parse_and_log_dns_response(payload, pkt_len, "Proxy (TCP)");

                    // Re-parse just to get IP for send_dns_response construction?
                    // Actually we need the IP to construct the UDP response. 
                    // But wait, parse_and_log_dns_response does NOT return the IP.
                    // We need to keep the original logic for constructing the response, 
                    // OR modify the helper to return the IP.
                    // For minimal risk, I will KEEP the original parsing logic for response construction,
                    // but REMOVE the logging and cache update from it, since helper does it.
                    
                    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
                    uint16_t an_count = ntohs(*(uint16_t*)(payload + 6));
                    
                    if ((flags & 0x8000) && an_count > 0) {
                        uint16_t qd_count = ntohs(*(uint16_t*)(payload + 4));
                        int pos = 12;
                        for(int i=0; i<qd_count; i++) {
                            while(pos < pkt_len) {
                                uint8_t n = payload[pos];
                                if(n==0) { pos++; break; }
                                if((n&0xC0)==0xC0) { pos+=2; break; }
                                pos += n+1;
                            }
                            pos += 4;
                        }
                        
                        for(int i=0; i<an_count; i++) {
                            if(pos >= pkt_len) break;
                            while(pos < pkt_len) {
                                uint8_t n = payload[pos];
                                if(n==0) { pos++; break; }
                                if((n&0xC0)==0xC0) { pos+=2; break; }
                                pos += n+1;
                            }
                            if(pos+10 > pkt_len) break;
                            uint16_t type = ntohs(*(uint16_t*)(payload+pos));
                            uint16_t rdlen = ntohs(*(uint16_t*)(payload+pos+8));
                            pos += 10;
                            
                            if (type == 1 && rdlen == 4 && pos + 4 <= pkt_len) {
                                uint32_t ip = *(uint32_t*)(payload + pos);
                                
                                // REWRITE Response
                                std::string target_domain = sess->original_domain_with_suffix.empty() ? sess->clean_domain : sess->original_domain_with_suffix;
                                send_dns_response(sess->src_ip, sess->original_dst_ip, sess->src_port, sess->original_dst_port, id, target_domain, ip);
                                goto next_packet;
                            }
                            pos += rdlen;
                        }
                    }
                    
                    next_packet:
                    sess->tcp_rx_buffer.erase(sess->tcp_rx_buffer.begin(), sess->tcp_rx_buffer.begin() + 2 + pkt_len);
                } else {
                    break; 
                }
            }
        }
    } else {
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

// Helper to build a standard DNS Query packet
std::vector<uint8_t> build_dns_query(uint16_t id, const std::string& domain) {
    std::vector<uint8_t> req;
    req.reserve(64);
    
    req.push_back(id & 0xFF); req.push_back((id >> 8) & 0xFF);
    req.push_back(0x01); req.push_back(0x00); // Flags: Std Query, Recurse
    req.push_back(0x00); req.push_back(0x01); // QD=1
    req.push_back(0x00); req.push_back(0x00); // AN=0
    req.push_back(0x00); req.push_back(0x00); 
    req.push_back(0x00); req.push_back(0x00); 
    
    size_t pos = 0;
    while (pos < domain.length()) {
        size_t next_dot = domain.find('.', pos);
        std::string label;
        if (next_dot == std::string::npos) {
            label = domain.substr(pos);
            pos = domain.length();
        } else {
            label = domain.substr(pos, next_dot - pos);
            pos = next_dot + 1;
        }
        if (label.length() > 63) label = label.substr(0, 63); 
        req.push_back((uint8_t)label.length());
        for (char c : label) req.push_back(c);
    }
    req.push_back(0); 
    
    req.push_back(0x00); req.push_back(0x01); // A
    req.push_back(0x00); req.push_back(0x01); // IN
    
    return req;
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

// Helper: Forward UDP packet directly
void forward_udp_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len) {
    // LOG_DEBUG("[UDP] Forward %d bytes: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", len,
    //    src_ip & 0xFF, (src_ip >> 8) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF, ntohs(src_port),
    //    dst_ip & 0xFF, (dst_ip >> 8) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 24) & 0xFF, ntohs(dst_port));

    uint32_t hash = src_port ^ dst_port ^ src_ip ^ dst_ip;
    Worker* w = WorkerPool::instance().get_worker(hash);
    if (!w) w = WorkerPool::instance().get_next_worker();

    std::vector<uint8_t> data(payload, payload + len);

    w->queue_task([src_ip, dst_ip, src_port, dst_port, data = std::move(data), w]() {
        UdpKey key = { src_ip, dst_ip, src_port, dst_port };
        UdpSession* sess = nullptr;
        auto it = t_udp_sessions.find(key);
        
        if (it != t_udp_sessions.end()) {
            sess = it->second;
        } else {
            LOG_INFO("[UDP] Direct Tunnel Established: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
                src_ip & 0xFF, (src_ip >> 8) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF, ntohs(src_port),
                dst_ip & 0xFF, (dst_ip >> 8) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 24) & 0xFF, ntohs(dst_port));

            sess = new UdpSession();
            sess->src_ip = src_ip; 
            sess->original_dst_ip = dst_ip; 
            sess->src_port = src_port; 
            sess->original_dst_port = dst_port;
            sess->worker = w;
            sess->is_dns_tcp = false;
            
            sess->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sess->udp_sock == INVALID_SOCKET) { delete sess; return; }
            u_long mode = 1; ioctlsocket(sess->udp_sock, FIONBIO, &mode);

            // Optimization: Increase UDP Buffer for Video/Streaming
            int buf_size = 1024 * 1024; // 1MB
            setsockopt(sess->udp_sock, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));
            setsockopt(sess->udp_sock, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
            
            t_udp_sessions[key] = sess;
            
            sess->worker->add_socket(
                sess->udp_sock,
                [sess]() { handle_udp_direct_read(sess); },
                nullptr,
                [sess]() { close_udp_session_internal(sess); }
            );
            
            sess->state = UdpSession::ESTABLISHED;
        }
        
        if (sess && sess->state != UdpSession::CLOSED) {
            sess->last_active = GetTickCount64();
            
            sockaddr_in dest_addr;
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_addr.S_un.S_addr = dst_ip;
            dest_addr.sin_port = dst_port; 
            
            sendto(sess->udp_sock, (const char*)data.data(), (int)data.size(), 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
        }
    });
}

// Called by Main Thread
void handle_udp_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len) {
    // 0. Drop Noisy Protocols (mDNS, NetBIOS, SSDP) - Check FIRST
    uint16_t dport_h = ntohs(dst_port);
    if (dport_h == 5353 ||  // mDNS
        dport_h == 5355 ||  // LLMNR
        dport_h == 137 ||   // NetBIOS Name Service
        dport_h == 138 ||   // NetBIOS Datagram Service
        dport_h == 1900) {  // SSDP (UPnP)
        return; // Drop immediately
    }

    // 1. UDP 443 (QUIC) Optimization
    if (dst_port == htons(443)) {
        std::string ip_bytes((char*)&dst_ip, 4);
        std::string country = GeoChecker::instance().query_ip(ip_bytes);
        
        // 如果 IP 属于 Google 或者是国外已知服务，可以进一步判定
        // 这里根据需求：如果是 Google 则 drop
        if (country == "GOOGLE") {
            LOG_INFO("[UDP] Blocked Google QUIC: %d.%d.%d.%d:443\n", 
                dst_ip & 0xFF, (dst_ip >> 8) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 24) & 0xFF);
            return;
        }

        // 尝试解析域名（QUIC SNI 探测较为复杂，这里先以 IP 判定为主，后续可扩展）
        // 如果不属于 Google，则走直连逻辑
        forward_udp_packet(src_ip, dst_ip, src_port, dst_port, payload, len);
        return;
    }

    // 2. UDP 53 (DNS) Optimization
    if (dst_port == htons(53)) {
        int qname_len = 0;
        std::string full_domain = parse_dns_qname(payload, len, &qname_len);
        
        if (!full_domain.empty()) {
            std::string clean_domain = full_domain;
            // ... (省略后缀处理逻辑，保持原样)
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

            uint16_t id = *(uint16_t*)payload;
            uint32_t cached_ip = DnsCache::instance().get(clean_domain);
            if (cached_ip != 0) {
                send_dns_response(src_ip, dst_ip, src_port, dst_port, id, full_domain, cached_ip);
                return;
            }

            bool domestic = GeoChecker::instance().is_cn_domain(clean_domain) || 
                            GeoChecker::instance().is_tencent_domain(clean_domain);
            
            if (domestic) {
                // 国内域名：不走 DNS-over-TCP，直接直连阿里 DNS
                // LOG_INFO("[DNS] Domestic Domain: %s. Using Direct UDP to 223.5.5.5\n", clean_domain.c_str());
                uint32_t ali_dns;
                uint8_t ali_ip[4] = {223, 5, 5, 5};
                memcpy(&ali_dns, ali_ip, 4);
                
                // 修改目标并直连转发
                forward_udp_packet(src_ip, ali_dns, src_port, dst_port, payload, len);
                return;
            } else {
                // 国外域名：继续走 DNS-over-TCP 代理
                uint32_t google_dns;
                uint8_t google_ip[4] = {8, 8, 8, 8};
                memcpy(&google_dns, google_ip, 4);

                // LOG_INFO("[DNS] International Domain: %s. Using DNS-over-TCP via Proxy\n", clean_domain.c_str());

                std::vector<uint8_t> query_packet;
                const uint8_t* p_data = payload;
                int p_len = len;
                if (stripped) {
                    query_packet = build_dns_query(id, clean_domain);
                    p_data = query_packet.data();
                    p_len = (int)query_packet.size();
                }

                uint32_t hash = src_port ^ dst_port ^ src_ip ^ dst_ip;
                Worker* w = WorkerPool::instance().get_worker(hash);
                if (!w) w = WorkerPool::instance().get_next_worker();
                std::vector<uint8_t> data(p_data, p_data + p_len);
                
                w->queue_task([src_ip, dst_ip, src_port, dst_port, google_dns, data = std::move(data), w, full_domain, clean_domain]() {
                    // ... (原有的 DNS-over-TCP 逻辑)
                    UdpKey key = { src_ip, dst_ip, src_port, dst_port };
                    UdpSession* sess = nullptr;
                    auto it = t_udp_sessions.find(key);
                    if (it == t_udp_sessions.end()) {
                        sess = new UdpSession();
                        sess->src_ip = src_ip; sess->original_dst_ip = dst_ip; 
                        sess->src_port = src_port; sess->original_dst_port = dst_port;
                        sess->proxy_target_ip = google_dns;
                        sess->proxy_target_port = htons(53);
                        sess->worker = w; sess->is_dns_tcp = true;
                        sess->original_domain_with_suffix = full_domain;
                        sess->clean_domain = clean_domain;
                        sess->tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
                        if (sess->tcp_sock == INVALID_SOCKET) { delete sess; return; }
                        u_long mode = 1; ioctlsocket(sess->tcp_sock, FIONBIO, &mode);
                        t_udp_sessions[key] = sess;
                        
                        sockaddr_in proxy_addr; memset(&proxy_addr, 0, sizeof(proxy_addr));
                        proxy_addr.sin_family = AF_INET;
                        unsigned int a,b,c,d;
                        if (sscanf_s(PROXY_IP, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                            proxy_addr.sin_addr.S_un.S_addr = (a) | (b << 8) | (c << 16) | (d << 24);
                        } else { proxy_addr.sin_addr.S_un.S_addr = 0x0100007F; }
                        proxy_addr.sin_port = htons(PROXY_PORT);
                        
                        sess->worker->connect_async(sess->tcp_sock, proxy_addr, [sess]() {
                            if (sess->state == UdpSession::CLOSED) return;
                            uint8_t req[] = { 0x05, 0x01, 0x00 };
                            send(sess->tcp_sock, (const char*)req, sizeof(req), 0);
                            sess->state = UdpSession::HANDSHAKE_AUTH;
                            sess->worker->add_socket(sess->tcp_sock, [sess]() { handle_socks5_tcp_read(sess); }, nullptr, [sess]() { close_udp_session_internal(sess); });
                        });
                    }
                    if (sess && sess->state != UdpSession::CLOSED) {
                        sess->last_active = GetTickCount64();
                        if (sess->state == UdpSession::ESTABLISHED) send_dns_over_tcp(sess, data);
                        else sess->pending_packets.push_back(std::move(data));
                    }
                });
                return;
            }
        }
    }

    // Default: Direct UDP Logic
    forward_udp_packet(src_ip, dst_ip, src_port, dst_port, payload, len);
}
