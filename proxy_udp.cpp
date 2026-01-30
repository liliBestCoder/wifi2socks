#include "proxy_udp.h"
#include "worker.h"
#include "tap_driver.h"
#include "app_config.h"
#include "lwip_handler.h"
#include <map>
#include <mutex>
#include <atomic>
#include <vector>

// --- UDP Session with Worker Pool ---
struct UdpKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    bool operator<(const UdpKey& o) const { return memcmp(this, &o, sizeof(UdpKey)) < 0; }
};

struct UdpSession {
    SOCKET sock;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    std::atomic<uint64_t> last_active;
    std::atomic<bool> closed;
    Worker* worker;
    UdpSession() : sock(INVALID_SOCKET), closed(false), worker(NULL) { last_active = GetTickCount64(); }
};

std::map<UdpKey, UdpSession*> g_udp_sessions;
std::mutex g_udp_mtx;

void close_udp_session(UdpSession* sess) {
    if (sess->closed.exchange(true)) return;
    if (sess->worker) sess->worker->remove_socket(sess->sock);
    if (sess->sock != INVALID_SOCKET) closesocket(sess->sock);
    
    // Remove from map
    {
        std::lock_guard<std::mutex> lk(g_udp_mtx);
        UdpKey key = { sess->src_ip, sess->dst_ip, sess->src_port, sess->dst_port };
        g_udp_sessions.erase(key);
    }
    delete sess;
}

void handle_udp_read(UdpSession* sess) {
    if (sess->closed) return;
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
             // Close handled by timeout
        }
    }
}

void udp_check_timeouts() {
     std::vector<UdpSession*> stale_sessions;
    {
        std::lock_guard<std::mutex> lk(g_udp_mtx);
        uint64_t now = GetTickCount64();
        for (auto& pair : g_udp_sessions) {
            if (now - pair.second->last_active > 60000) {
                stale_sessions.push_back(pair.second);
            }
        }
    }
    for (auto* sess : stale_sessions) {
        close_udp_session(sess);
    }
}

void handle_udp_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len) {
    UdpKey key = { src_ip, dst_ip, src_port, dst_port };
    UdpSession* sess = NULL;
    {
        std::lock_guard<std::mutex> lk(g_udp_mtx);
        auto it = g_udp_sessions.find(key);
        if (it != g_udp_sessions.end()) sess = it->second;
    }

    if (!sess) {
        sess = new UdpSession();
        sess->src_ip = src_ip; sess->dst_ip = dst_ip;
        sess->src_port = src_port; sess->dst_port = dst_port;
        sess->sock = socket(AF_INET, SOCK_DGRAM, 0);

        if (sess->sock != INVALID_SOCKET) {
            u_long mode = 1;
            ioctlsocket(sess->sock, FIONBIO, &mode);

            sess->worker = WorkerPool::instance().get_worker(src_port ^ dst_port);
            if (!sess->worker) sess->worker = WorkerPool::instance().get_next_worker();

            {
                std::lock_guard<std::mutex> lk(g_udp_mtx);
                g_udp_sessions[key] = sess;
            }

            sess->worker->add_socket(
                sess->sock,
                [sess]() { handle_udp_read(sess); },
                nullptr,
                [sess]() { close_udp_session(sess); }
            );

        } else {
            delete sess; sess = NULL;
        }
    }

    if (sess) {
        sess->last_active = GetTickCount64();
        sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_addr.S_un.S_addr = sess->dst_ip;
        dest.sin_port = sess->dst_port;
        sendto(sess->sock, (const char*)payload, len, 0, (sockaddr*)&dest, sizeof(dest));
    }
}