#include "proxy_udp.h"
#include "worker.h"
#include "tap_driver.h"
#include "app_config.h"
#include "lwip_handler.h"
#include <map>
#include <vector>
#include <deque>

// --- UDP Session (Thread Local) ---
struct UdpKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    bool operator<(const UdpKey& o) const { return memcmp(this, &o, sizeof(UdpKey)) < 0; }
};

struct UdpSession {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint64_t last_active;
    Worker* worker;
    
    // Direct UDP Socket
    SOCKET udp_sock; 
    
    enum State { ESTABLISHED, CLOSED } state;

    UdpSession() : udp_sock(INVALID_SOCKET), worker(NULL), state(ESTABLISHED) { 
        last_active = GetTickCount64(); 
    }
};

thread_local std::map<UdpKey, UdpSession*> t_udp_sessions;

// Simple DNS Parser & Builder
void handle_dns_fake_ip(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len) {
    if (len < 12) return;
    
    // Parse ID
    uint16_t id = *(uint16_t*)payload; // Network Order
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    uint16_t qd_count = ntohs(*(uint16_t*)(payload + 4));
    
    if ((flags & 0x8000) != 0) return; // Ignore responses
    if (qd_count != 1) return; // Only handle single query

    // Find end of Query Name
    int pos = 12;
    while (pos < len) {
        uint8_t n = payload[pos];
        if (n == 0) { pos++; break; }
        pos += n + 1;
    }
    
    // Query Type (2) + Class (2)
    if (pos + 4 > len) return;
    uint16_t q_type = ntohs(*(uint16_t*)(payload + pos));
    // uint16_t q_class = ntohs(*(uint16_t*)(payload + pos + 2));
    pos += 4;

    if (q_type != 1) return; // Only handle A records (IPv4)

    // Construct Response
    // Header (12) + Question (pos-12) + Answer (16)
    // Answer: NamePtr(2) + Type(2) + Class(2) + TTL(4) + Len(2) + IP(4)
    std::vector<uint8_t> resp;
    resp.reserve(pos + 16);
    
    // Header
    resp.push_back(id & 0xFF); resp.push_back((id >> 8) & 0xFF); // ID
    // Flags: Response, Recursion Desired, Recursion Available, No Error
    // 0x8180
    resp.push_back(0x81); resp.push_back(0x80); 
    resp.push_back(0x00); resp.push_back(0x01); // QDCOUNT = 1
    resp.push_back(0x00); resp.push_back(0x01); // ANCOUNT = 1
    resp.push_back(0x00); resp.push_back(0x00); // NSCOUNT = 0
    resp.push_back(0x00); resp.push_back(0x00); // ARCOUNT = 0
    
    // Question Section (Copy from request)
    resp.insert(resp.end(), payload + 12, payload + pos);
    
    // Answer Section
    // Name Pointer: 0xC00C (Pointer to offset 12)
    resp.push_back(0xC0); resp.push_back(0x0C);
    
    // Type: A (1)
    resp.push_back(0x00); resp.push_back(0x01);
    // Class: IN (1)
    resp.push_back(0x00); resp.push_back(0x01);
    // TTL: 60 seconds
    resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x3C);
    // Data Length: 4
    resp.push_back(0x00); resp.push_back(0x04);
    // Data: 198.18.0.1 (Fake IP)
    // 198.18.0.1 = C6.12.00.01
    resp.push_back(198); resp.push_back(18); resp.push_back(0); resp.push_back(1);

    // Send back to Tap
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
    *(uint32_t*)(ip + 12) = dst_ip; // Src IP = DNS Server (8.8.8.8 etc)
    *(uint32_t*)(ip + 16) = src_ip; // Dst IP = Client
    *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

    *(uint16_t*)(udp_hdr + 0) = dst_port; 
    *(uint16_t*)(udp_hdr + 2) = src_port; 
    *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + resp.size()));
    *(uint16_t*)(udp_hdr + 6) = 0;
    memcpy(udp_hdr + 8, resp.data(), resp.size());

    TapDriver::instance().send_async(frame, 14 + 20 + 8 + (int)resp.size());
    
    printf("[FakeDNS] Hijacked query. Returned 198.18.0.1\n");
}

void close_udp_session_internal(UdpSession* sess) {
    if (!sess) return;
    
    UdpKey key = { sess->src_ip, sess->dst_ip, sess->src_port, sess->dst_port };
    t_udp_sessions.erase(key);

    if (sess->worker && sess->udp_sock != INVALID_SOCKET) {
        sess->worker->remove_socket(sess->udp_sock, [sess]() {
            closesocket(sess->udp_sock);
            delete sess;
        });
    } else {
        if (sess->udp_sock != INVALID_SOCKET) closesocket(sess->udp_sock);
        delete sess;
    }
}

void handle_direct_udp_read(UdpSession* sess) {
    char buf[4096];
    sockaddr_in from;
    int from_len = sizeof(from);
    int r = recvfrom(sess->udp_sock, buf, sizeof(buf), 0, (sockaddr*)&from, &from_len);
    
    if (r > 0) {
        sess->last_active = GetTickCount64();
        
        // Check Source IP? 
        // Ideally we should verify 'from' address matches the session target, 
        // but for NAT we usually accept response.
        
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
    // 1. Drop QUIC (UDP 443)
    if (dst_port == htons(443)) {
        return; 
    }

    // 2. FakeIP for DNS (UDP 53)
    if (dst_port == htons(53)) {
        handle_dns_fake_ip(src_ip, dst_ip, src_port, dst_port, payload, len);
        return;
    }

    // 3. Direct Connection for others
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
            
            // Create Raw UDP Socket
            sess->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sess->udp_sock == INVALID_SOCKET) { delete sess; return; }
            u_long mode = 1; ioctlsocket(sess->udp_sock, FIONBIO, &mode);
            
            t_udp_sessions[key] = sess;
            
            sockaddr_in local;
            memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET;
            local.sin_addr.S_un.S_addr = INADDR_ANY;
            local.sin_port = 0;
            bind(sess->udp_sock, (sockaddr*)&local, sizeof(local));
            
            sess->worker->add_socket(
                sess->udp_sock,
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
            
            sendto(sess->udp_sock, (const char*)data.data(), (int)data.size(), 0, (sockaddr*)&dest, sizeof(dest));
        }
    });
}