#include "proxy_udp.h"
#include "worker.h"
#include "tap_driver.h"
#include "app_config.h"
#include "lwip_handler.h"
#include "nat_table.h"
#include <map>
#include <vector>
#include <deque>
#include <string>

// --- UDP Session (Native Direct) ---
// Since we are doing direct connection for non-DNS UDP, we just map 
// Key -> Socket.
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
    
    UdpSession() : sock(INVALID_SOCKET), worker(NULL) { 
        last_active = GetTickCount64(); 
    }
};

thread_local std::map<UdpKey, UdpSession*> t_udp_sessions;

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

void handle_direct_udp_read(UdpSession* sess) {
    char buf[4096];
    sockaddr_in from;
    int from_len = sizeof(from);
    int r = recvfrom(sess->sock, buf, sizeof(buf), 0, (sockaddr*)&from, &from_len);
    
    if (r > 0) {
        sess->last_active = GetTickCount64();
        
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
        *(uint32_t*)(ip + 12) = sess->dst_ip; // Src = Server
        *(uint32_t*)(ip + 16) = sess->src_ip; // Dst = Client
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
        if ((n & 0xC0) == 0xC0) return ""; // Pointers not expected in Query
        
        if (pos + n + 1 > len) return "";
        
        if (!domain.empty()) domain += ".";
        domain.append((char*)(payload + pos + 1), n);
        pos += n + 1;
    }
    
    if (qname_len) *qname_len = pos - 12;
    return domain;
}

void handle_dns_fake_ip(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len) {
    if (len < 12) return; 
    
    // Parse ID, Flags
    uint16_t id = *(uint16_t*)payload;
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    uint16_t qd_count = ntohs(*(uint16_t*)(payload + 4));
    
    if ((flags & 0x8000) != 0) return; // Response
    if (qd_count != 1) return; 

    int qname_len = 0;
    std::string domain = parse_dns_qname(payload, len, &qname_len);
    if (domain.empty()) return;
    
    // Check type (A=1)
    int pos = 12 + qname_len;
    if (pos + 4 > len) return;
    uint16_t q_type = ntohs(*(uint16_t*)(payload + pos));
    if (q_type != 1) return; // Only FakeIP for A records

    // Get Fake IP
    uint32_t fake_ip = FakeIpMapper::instance().get_fake_ip(domain);
    
    printf("[FakeDNS] Query: %s -> FakeIP: %d.%d.%d.%d\n", domain.c_str(), 
        fake_ip & 0xFF, (fake_ip >> 8) & 0xFF, (fake_ip >> 16) & 0xFF, (fake_ip >> 24) & 0xFF);

    // Build Response
    std::vector<uint8_t> resp;
    resp.reserve(512);
    
    // Header
    resp.push_back(id & 0xFF); resp.push_back((id >> 8) & 0xFF);
    resp.push_back(0x81); resp.push_back(0x80); // Flags: Std Response, No Error
    resp.push_back(0x00); resp.push_back(0x01); // QD=1
    resp.push_back(0x00); resp.push_back(0x01); // AN=1
    resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x00); resp.push_back(0x00);
    
    // Question Section
    resp.insert(resp.end(), payload + 12, payload + pos + 4);
    
    // Answer Section
    // Name Pointer -> 0xC00C
    resp.push_back(0xC0); resp.push_back(0x0C);
    // Type A (1)
    resp.push_back(0x00); resp.push_back(0x01);
    // Class IN (1)
    resp.push_back(0x00); resp.push_back(0x01);
    // TTL: 1 second (Don't cache long to avoid issues on restart)
    resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x01);
    // Len (4)
    resp.push_back(0x00); resp.push_back(0x04);
    // IP
    resp.push_back(fake_ip & 0xFF);
    resp.push_back((fake_ip >> 8) & 0xFF);
    resp.push_back((fake_ip >> 16) & 0xFF);
    resp.push_back((fake_ip >> 24) & 0xFF);
    
    // Send
    uint8_t frame[2048];
    if (14 + 20 + 8 + resp.size() > 2048) return;

    memcpy(frame, HOST_MAC, 6);
    memcpy(frame + 6, TapDriver::TAP_MAC, 6);
    *(uint16_t*)(frame + 12) = htons(0x0800);

    uint8_t* ip = frame + 14;
    uint8_t* udp_hdr = ip + 20;
    
    memset(ip, 0, 20);
    ip[0] = 0x45; ip[9] = 17; ip[8] = 64;
    *(uint16_t*)(ip + 2) = htons((uint16_t)(20 + 8 + resp.size()));
    *(uint32_t*)(ip + 12) = dst_ip; 
    *(uint32_t*)(ip + 16) = src_ip; 
    *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

    *(uint16_t*)(udp_hdr + 0) = dst_port; 
    *(uint16_t*)(udp_hdr + 2) = src_port; 
    *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + resp.size()));
    *(uint16_t*)(udp_hdr + 6) = 0;
    memcpy(udp_hdr + 8, resp.data(), resp.size());

    TapDriver::instance().send_async(frame, 14 + 20 + 8 + (int)resp.size());
}

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

void handle_udp_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len) {
    // 1. DROP QUIC
    if (dst_port == htons(443)) return;

    // 2. FakeDNS for Port 53
    if (dst_port == htons(53)) {
        handle_dns_fake_ip(src_ip, dst_ip, src_port, dst_port, payload, len);
        return;
    }

    // 3. Direct UDP for others
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
            if (sess->sock == INVALID_SOCKET) { delete sess; return; }
            u_long mode = 1; ioctlsocket(sess->sock, FIONBIO, &mode);
            
            t_udp_sessions[key] = sess;
            
            // Bind ANY
            sockaddr_in local;
            memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET;
            local.sin_addr.S_un.S_addr = INADDR_ANY;
            local.sin_port = 0;
            bind(sess->sock, (sockaddr*)&local, sizeof(local));
            
            sess->worker->add_socket(
                sess->sock,
                [sess]() { handle_direct_udp_read(sess); },
                nullptr, 
                [sess]() { close_udp_session_internal(sess); }
            );
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
