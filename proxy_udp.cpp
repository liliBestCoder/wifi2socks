#include "proxy_udp.h"
#include "worker.h"
#include "tap_driver.h"
#include "app_config.h"
#include "lwip_handler.h"
#include <map>
#include <vector>

// --- UDP Session (Thread Local) ---
struct UdpKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    bool operator<(const UdpKey& o) const { return memcmp(this, &o, sizeof(UdpKey)) < 0; }
};

struct UdpSession {
    SOCKET sock;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint64_t last_active; // No atomic needed, accessed only by worker thread
    Worker* worker;
    UdpSession() : sock(INVALID_SOCKET), worker(NULL) { last_active = GetTickCount64(); }
};

// Thread-local storage for sessions. 
// No locking needed as it's accessed only by the owning worker thread.
thread_local std::map<UdpKey, UdpSession*> t_udp_sessions;

void close_udp_session_internal(UdpSession* sess) {
    if (!sess) return;
    
    // Remove from thread-local map first
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

void handle_udp_read(UdpSession* sess) {
    char buf[2048];
    sockaddr_in from;
    int from_len = sizeof(from);
    int r = recvfrom(sess->sock, buf, sizeof(buf), 0, (sockaddr*)&from, &from_len);
    
    if (r > 0 && g_host_mac_known) {
        sess->last_active = GetTickCount64();
        // Construct Reply
        uint8_t frame[2048];
        if (14 + 20 + 8 + r > 2048) return;

        memcpy(frame, HOST_MAC, 6);
        memcpy(frame + 6, TapDriver::TAP_MAC, 6);
        *(uint16_t*)(frame + 12) = htons(0x0800);

        uint8_t* ip = frame + 14;
        uint8_t* udp_hdr = ip + 20;
        
        // IPv4 Header
        memset(ip, 0, 20);
        ip[0] = 0x45; ip[9] = 17; ip[8] = 64;
        *(uint16_t*)(ip + 2) = htons((uint16_t)(20 + 8 + r));
        *(uint32_t*)(ip + 12) = sess->dst_ip;
        *(uint32_t*)(ip + 16) = sess->src_ip;
        *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

        // UDP Header
        *(uint16_t*)(udp_hdr + 0) = sess->dst_port;
        *(uint16_t*)(udp_hdr + 2) = sess->src_port;
        *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + r));
        *(uint16_t*)(udp_hdr + 6) = 0;
        memcpy(udp_hdr + 8, buf, r);

        TapDriver::instance().send_async(frame, 14 + 20 + 8 + r);
    } else if (r == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
             // Let timeout handle close, or close immediately?
             // Closing immediately is safer for resources.
             close_udp_session_internal(sess);
        }
    }
}

// Called by Main Thread
void udp_check_timeouts() {
    // Dispatch cleanup task to ALL workers
    WorkerPool::instance().for_each_worker([](Worker* w) {
        w->queue_task([]() {
            uint64_t now = GetTickCount64();
            std::vector<UdpSession*> stale_sessions;
            
            // Iterate thread-local map
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
    // 1. Calculate Hash to pick a worker
    uint32_t hash = src_port ^ dst_port ^ src_ip ^ dst_ip;
    Worker* w = WorkerPool::instance().get_worker(hash);
    if (!w) w = WorkerPool::instance().get_next_worker();
    
    // 2. Copy data (Must deep copy as payload is valid only in this scope)
    std::vector<uint8_t> data(payload, payload + len);
    
    // 3. Queue task to worker
    w->queue_task([src_ip, dst_ip, src_port, dst_port, data = std::move(data), w]() {
        // Runs inside Worker Thread
        UdpKey key = { src_ip, dst_ip, src_port, dst_port };
        UdpSession* sess = nullptr;
        
        auto it = t_udp_sessions.find(key);
        if (it != t_udp_sessions.end()) {
            sess = it->second;
        } else {
            // New Session
            sess = new UdpSession();
            sess->src_ip = src_ip; sess->dst_ip = dst_ip;
            sess->src_port = src_port; sess->dst_port = dst_port;
            sess->worker = w;
            sess->sock = socket(AF_INET, SOCK_DGRAM, 0);
            
            if (sess->sock != INVALID_SOCKET) {
                u_long mode = 1;
                ioctlsocket(sess->sock, FIONBIO, &mode);
                
                t_udp_sessions[key] = sess;
                
                // Add to poll loop
                sess->worker->add_socket(
                    sess->sock,
                    [sess]() { handle_udp_read(sess); },
                    nullptr,
                    [sess]() { close_udp_session_internal(sess); }
                );
            } else {
                delete sess;
                sess = nullptr;
            }
        }
        
        if (sess) {
            sess->last_active = GetTickCount64();
            sockaddr_in dest;
            dest.sin_family = AF_INET;
            
            // DNS Hijack: Redirect all DNS to 8.8.8.8 (Google DNS)
            if (sess->dst_port == htons(53)) {
                dest.sin_addr.S_un.S_addr = 0x08080808; 
            } else {
                dest.sin_addr.S_un.S_addr = sess->dst_ip;
            }

            dest.sin_port = sess->dst_port;
            sendto(sess->sock, (const char*)data.data(), (int)data.size(), 0, (sockaddr*)&dest, sizeof(dest));
        }
    });
}
