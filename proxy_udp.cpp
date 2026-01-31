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
    SOCKET sock;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint64_t last_active;
    Worker* worker;
    
    // DNS Reconstruction State
    std::string original_domain_with_suffix; 
    
    UdpSession() : sock(INVALID_SOCKET), worker(NULL) { 
        last_active = GetTickCount64(); 
    }
};

thread_local std::map<UdpKey, UdpSession*> t_udp_sessions;

// Helper to log DNS answers
void log_dns_packet(const uint8_t* payload, int len) {
    if (len < 12) return;
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    uint16_t an_count = ntohs(*(uint16_t*)(payload + 6));
    if ((flags & 0x8000) == 0 || an_count == 0) return;

    printf("[DNS] Received %d Answers (Packet Len: %d)\n", an_count, len);

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
        while (pos < len) {
            uint8_t n = payload[pos];
            if (n == 0) { pos++; break; }
            if ((n & 0xC0) == 0xC0) { pos += 2; break; }
            pos += n + 1;
        }
        
        if (pos + 10 > len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(payload + pos));
        uint16_t rdlen = ntohs(*(uint16_t*)(payload + pos + 8)); // Correct offset for RDLen
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

void close_udp_session_internal(UdpSession* sess) {
    if (!sess) return; 
    
    UdpKey key = { sess->src_ip, sess->dst_ip, sess->src_port, sess->dst_port };
    t_udp_sessions.erase(key);

    if (sess->worker && sess->sock != INVALID_SOCKET) {
        sess->worker->remove_socket(sess->sock, [sess]() {
            closesocket(sess->sock);
            delete sess;
        });
    } else {
        if (sess->sock != INVALID_SOCKET) closesocket(sess->sock);
        delete sess;
    }
}

// Helper to build a DNS Response
void send_dns_response(UdpSession* sess, uint16_t id, const std::string& domain, uint32_t ip_addr) {
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
    resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x01); // TTL=1
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
    *(uint32_t*)(ip_hdr + 12) = sess->dst_ip; 
    *(uint32_t*)(ip_hdr + 16) = sess->src_ip; 
    *(uint16_t*)(ip_hdr + 10) = ip_chksum_simple(ip_hdr, 20);

    *(uint16_t*)(udp_hdr + 0) = sess->dst_port; 
    *(uint16_t*)(udp_hdr + 2) = sess->src_port; 
    *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + resp.size()));
    *(uint16_t*)(udp_hdr + 6) = 0;
    memcpy(udp_hdr + 8, resp.data(), resp.size());

    TapDriver::instance().send_async(frame, 14 + 20 + 8 + (int)resp.size());
}

void handle_direct_udp_read(UdpSession* sess) {
    char buf[4096];
    sockaddr_in from;
    int from_len = sizeof(from);
    int r = recvfrom(sess->sock, buf, sizeof(buf), 0, (sockaddr*)&from, &from_len);
    
    if (r > 0) {
        sess->last_active = GetTickCount64();
        
        // INTERCEPT: DNS Response Rewrite
        if (!sess->original_domain_with_suffix.empty() && r > 12) {
            uint8_t* payload = (uint8_t*)buf;
            uint16_t id = *(uint16_t*)payload;
            uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
            uint16_t an_count = ntohs(*(uint16_t*)(payload + 6));
            
            if ((flags & 0x8000) && an_count > 0) {
                // Parse to find the IP
                uint16_t qd_count = ntohs(*(uint16_t*)(payload + 4));
                int pos = 12;
                // Skip Query
                for(int i=0; i<qd_count; i++) {
                    while(pos < r) {
                        uint8_t n = payload[pos];
                        if(n==0) { pos++; break; }
                        if((n&0xC0)==0xC0) { pos+=2; break; }
                        pos += n+1;
                    }
                    pos += 4;
                }
                
                // Scan Answers
                for(int i=0; i<an_count; i++) {
                    if(pos >= r) break;
                    // Skip Name
                    while(pos < r) {
                        uint8_t n = payload[pos];
                        if(n==0) { pos++; break; }
                        if((n&0xC0)==0xC0) { pos+=2; break; }
                        pos += n+1;
                    }
                    if(pos+10 > r) break;
                    uint16_t type = ntohs(*(uint16_t*)(payload+pos));
                    uint16_t rdlen = ntohs(*(uint16_t*)(payload+pos+8));
                    pos += 10;
                    
                    if (type == 1 && rdlen == 4 && pos + 4 <= r) {
                        uint32_t ip = *(uint32_t*)(payload + pos);
                        send_dns_response(sess, id, sess->original_domain_with_suffix, ip);
                        printf("[SmartDNS] Fixed suffix: %s -> %d.%d.%d.%d\n", 
                            sess->original_domain_with_suffix.c_str(),
                            ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
                        return; // Done
                    }
                    pos += rdlen;
                }
            }
        }

        uint8_t frame[2048];
        if (14 + 20 + 8 + r > 2048) return;

        memcpy(frame, HOST_MAC, 6);
        memcpy(frame + 6, TapDriver::TAP_MAC, 6);
        *(uint16_t*)(frame + 12) = htons(0x0800);

        uint8_t* ip = frame + 14;
        uint8_t* udp_hdr = ip + 20;
        
        memset(ip, 0, 20);
        ip[0] = 0x45; ip[9] = 17; ip[8] = 64;
        *(uint16_t*)(ip + 2) = htons((uint16_t)(20 + 8 + r));
        *(uint32_t*)(ip + 12) = sess->dst_ip; 
        *(uint32_t*)(ip + 16) = sess->src_ip; 
        *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

        *(uint16_t*)(udp_hdr + 0) = sess->dst_port; 
        *(uint16_t*)(udp_hdr + 2) = sess->src_port; 
        *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + r));
        *(uint16_t*)(udp_hdr + 6) = 0;
        memcpy(udp_hdr + 8, buf, r);

        TapDriver::instance().send_async(frame, 14 + 20 + 8 + r);
    } else if (r == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
             close_udp_session_internal(sess);
        }
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
    req.push_back(0x01); req.push_back(0x00); // Flags
    req.push_back(0x00); req.push_back(0x01); // QD=1
    req.push_back(0x00); req.push_back(0x00); 
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

void handle_dns_fake_ip(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len, const std::string& domain) {
    if (len < 12) return; 
    
    uint16_t id = *(uint16_t*)payload;
    uint32_t fake_ip = FakeIpMapper::instance().get_fake_ip(domain);
    
    // We can reuse the send_dns_response function by creating a dummy session context
    UdpSession sess;
    sess.src_ip = src_ip; sess.dst_ip = dst_ip; 
    sess.src_port = src_port; sess.dst_port = dst_port;
    
    send_dns_response(&sess, id, domain, fake_ip);
    
    printf("[FakeDNS] Query: %s -> FakeIP: %d.%d.%d.%d\n", domain.c_str(), 
        fake_ip & 0xFF, (fake_ip >> 8) & 0xFF, (fake_ip >> 16) & 0xFF, (fake_ip >> 24) & 0xFF);
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

    // 2. DNS Handling
    if (dst_port == htons(53)) {
        int qname_len = 0;
        std::string full_domain = parse_dns_qname(payload, len, &qname_len);
        
        if (!full_domain.empty()) {
            std::string clean_domain = full_domain;
            std::string temp = full_domain;
            // Lowercase
            std::transform(temp.begin(), temp.end(), temp.begin(), ::tolower);
            
            // Simplified Suffix Stripping
            const char* suffixes[] = { ".mshome.net", ".lan", ".local" };
            bool stripped = false;
            for (const char* suf : suffixes) {
                size_t suflen = strlen(suf);
                if (temp.length() > suflen && temp.compare(temp.length() - suflen, suflen, suf) == 0) {
                    clean_domain = full_domain.substr(0, full_domain.length() - suflen);
                    stripped = true;
                    printf("[SmartDNS] Stripped suffix: %s -> %s\n", full_domain.c_str(), clean_domain.c_str());
                    break;
                }
            }

            if (!DomainRules::instance().is_domestic(clean_domain)) {
                // Foreign -> FakeIP
                handle_dns_fake_ip(src_ip, dst_ip, src_port, dst_port, payload, len, clean_domain);
                return;
            }
            
            // Domestic -> Direct to AliDNS
            printf("[Direct-DNS] Domestic: %s -> Forwarding to 223.5.5.5\n", clean_domain.c_str());
            
            // Prepare Query (Modify ID if needed? No, keep ID)
            // If stripped, we MUST rebuild the packet to query the clean name
            std::vector<uint8_t> query_packet;
            const uint8_t* p_data = payload;
            int p_len = len;
            
            if (stripped) {
                uint16_t id = *(uint16_t*)payload;
                query_packet = build_dns_query(id, clean_domain);
                p_data = query_packet.data();
                p_len = (int)query_packet.size();
            }

            // Create Session
            uint32_t hash = src_port ^ dst_port ^ src_ip ^ dst_ip;
            Worker* w = WorkerPool::instance().get_worker(hash);
            if (!w) w = WorkerPool::instance().get_next_worker();
            
            // Copy data for lambda
            std::vector<uint8_t> data(p_data, p_data + p_len);
            
            w->queue_task([src_ip, dst_ip, src_port, dst_port, data = std::move(data), w, full_domain, stripped]() {
                UdpKey key = { src_ip, dst_ip, src_port, dst_port };
                UdpSession* sess = nullptr;
                auto it = t_udp_sessions.find(key);
                if (it != t_udp_sessions.end()) {
                    sess = it->second;
                } else {
                    sess = new UdpSession();
                    sess->src_ip = src_ip; sess->dst_ip = dst_ip; 
                    sess->src_port = src_port; sess->dst_port = dst_port;
                    sess->worker = w;
                    if (stripped) sess->original_domain_with_suffix = full_domain;
                    
                    sess->sock = socket(AF_INET, SOCK_DGRAM, 0);
                    u_long mode = 1; ioctlsocket(sess->sock, FIONBIO, &mode);
                    
                    t_udp_sessions[key] = sess;
                    
                    sockaddr_in local; memset(&local, 0, sizeof(local));
                    local.sin_family = AF_INET; local.sin_addr.S_un.S_addr = INADDR_ANY; local.sin_port = 0;
                    bind(sess->sock, (sockaddr*)&local, sizeof(local));
                    
                    sess->worker->add_socket(sess->sock, [sess](){ handle_direct_udp_read(sess); }, nullptr, [sess](){ close_udp_session_internal(sess); });
                }
                
                if (sess) {
                    sess->last_active = GetTickCount64();
                    sockaddr_in dest; memset(&dest, 0, sizeof(dest)); dest.sin_family = AF_INET;
                    
                    // Force target to AliDNS
                    uint8_t ali[4] = {223, 5, 5, 5};
                    memcpy(&dest.sin_addr.S_un.S_addr, ali, 4);
                    dest.sin_port = dst_port;
                    
                    sendto(sess->sock, (const char*)data.data(), (int)data.size(), 0, (sockaddr*)&dest, sizeof(dest));
                }
            });
            return;
        }
    }

    // 3. Other UDP -> Direct
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
            sess = new UdpSession();
            sess->src_ip = src_ip; sess->dst_ip = dst_ip; 
            sess->src_port = src_port; sess->dst_port = dst_port;
            sess->worker = w;
            
            sess->sock = socket(AF_INET, SOCK_DGRAM, 0);
            u_long mode = 1; ioctlsocket(sess->sock, FIONBIO, &mode);
            
            t_udp_sessions[key] = sess;
            
            sockaddr_in local; memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET; local.sin_addr.S_un.S_addr = INADDR_ANY; local.sin_port = 0;
            bind(sess->sock, (sockaddr*)&local, sizeof(local));
            
            sess->worker->add_socket(sess->sock, [sess](){ handle_direct_udp_read(sess); }, nullptr, [sess](){ close_udp_session_internal(sess); });
        }
        
        if (sess) {
            sess->last_active = GetTickCount64();
            sockaddr_in dest;
            dest.sin_family = AF_INET;
            dest.sin_addr.S_un.S_addr = dst_ip;
            dest.sin_port = dst_port;
            sendto(sess->sock, (const char*)data.data(), (int)data.size(), 0, (sockaddr*)&dest, sizeof(dest));
        }
    });
}
