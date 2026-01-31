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
    
    // SOCKS5 State
    SOCKET tcp_sock; // Control Channel
    SOCKET udp_sock; // Data Channel (Relay)
    
    sockaddr_in relay_addr;
    
    enum State { CONNECTING, HANDSHAKE_AUTH, HANDSHAKE_ASSOC, ESTABLISHED, CLOSED } state;
    std::deque<std::vector<uint8_t>> pending_packets;

    UdpSession() : tcp_sock(INVALID_SOCKET), udp_sock(INVALID_SOCKET), worker(NULL), state(CONNECTING) { 
        last_active = GetTickCount64(); 
        memset(&relay_addr, 0, sizeof(relay_addr));
    }
};

thread_local std::map<UdpKey, UdpSession*> t_udp_sessions;

// Helper to log DNS answers for debugging
void log_dns_packet(const uint8_t* payload, int len) {
    if (len < 12) return;
    
    // Header: ID (2), Flags (2), QD(2), AN(2), ...
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    bool is_response = (flags & 0x8000) != 0;
    
    if (!is_response) return; 

    uint16_t an_count = ntohs(*(uint16_t*)(payload + 6));
    if (an_count == 0) return;

    // We only do a rough skip of Queries to get to Answers
    uint16_t qd_count = ntohs(*(uint16_t*)(payload + 4));
    int pos = 12;

    // Skip Queries
    for (int i=0; i<qd_count; ++i) {
        if (pos >= len) return;
        while (pos < len) {
            uint8_t n = payload[pos];
            if (n == 0) { pos++; break; }
            if ((n & 0xC0) == 0xC0) { pos += 2; break; } // Pointer
            pos += n + 1;
        }
        pos += 4; // Type(2), Class(2)
    }

    printf("[DNS] Received %d Answers:\n", an_count);

    // Parse Answers
    for (int i=0; i<an_count; ++i) {
        if (pos >= len) break;
        // Skip Name
        while (pos < len) {
            uint8_t n = payload[pos];
            if (n == 0) { pos++; break; }
            if ((n & 0xC0) == 0xC0) { pos += 2; break; }
            pos += n + 1;
        }
        
        if (pos + 10 > len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(payload + pos));
        pos += 2; // Type
        pos += 2; // Class
        pos += 4; // TTL
        uint16_t rdlen = ntohs(*(uint16_t*)(payload + pos));
        pos += 2; // RDLength
        
        if (pos + rdlen > len) break;
        
        if (type == 1 && rdlen == 4) { // A Record (IPv4)
            printf("  -> IPv4: %d.%d.%d.%d\n", 
                payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]);
        }
        pos += rdlen;
    }
}

void close_udp_session_internal(UdpSession* sess) {
    if (!sess) return;
    
    UdpKey key = { sess->src_ip, sess->dst_ip, sess->src_port, sess->dst_port };
    t_udp_sessions.erase(key);

    if (sess->worker) {
        // Need to remove potentially two sockets
        auto worker = sess->worker;
        
        // Helper to delete session only after both sockets are removed
        // We use a simple counter mechanism or just sequential removal.
        // Since callbacks are sequential in worker, we can nest them.
        
        SOCKET s1 = sess->tcp_sock;
        SOCKET s2 = sess->udp_sock;
        
        sess->tcp_sock = INVALID_SOCKET;
        sess->udp_sock = INVALID_SOCKET;
        sess->state = UdpSession::CLOSED;

        auto cleanup_stage2 = [s2, sess, worker]() {
            if (s2 != INVALID_SOCKET) {
                worker->remove_socket(s2, [s2, sess]() {
                    closesocket(s2);
                    delete sess;
                });
            } else {
                delete sess;
            }
        };

        if (s1 != INVALID_SOCKET) {
            worker->remove_socket(s1, [s1, cleanup_stage2]() {
                closesocket(s1);
                cleanup_stage2();
            });
        } else {
            cleanup_stage2();
        }
    } else {
        if (sess->tcp_sock != INVALID_SOCKET) closesocket(sess->tcp_sock);
        if (sess->udp_sock != INVALID_SOCKET) closesocket(sess->udp_sock);
        delete sess;
    }
}

void send_udp_to_relay(UdpSession* sess, const std::vector<uint8_t>& payload) {
    if (sess->state != UdpSession::ESTABLISHED || sess->udp_sock == INVALID_SOCKET) return;

    // SOCKS5 UDP Request Header
    // RSV(2) FRAG(1) ATYP(1) DST.ADDR(4) DST.PORT(2) DATA
    std::vector<uint8_t> packet;
    packet.reserve(10 + payload.size());
    
    packet.push_back(0x00); packet.push_back(0x00); // RSV
    packet.push_back(0x00); // FRAG
    packet.push_back(0x01); // ATYP: IPv4
    
    // Destination IP (Original Target) - Network Order
    uint32_t target_ip = sess->dst_ip;
    // DNS Hijack: Redirect all DNS to 8.8.8.8 (Google DNS)
    if (sess->dst_port == htons(53)) {
        target_ip = 0x08080808; 
    }

    packet.push_back(target_ip & 0xFF);
    packet.push_back((target_ip >> 8) & 0xFF);
    packet.push_back((target_ip >> 16) & 0xFF);
    packet.push_back((target_ip >> 24) & 0xFF);
    
    // Destination Port - Network Order
    packet.push_back(sess->dst_port & 0xFF);
    packet.push_back((sess->dst_port >> 8) & 0xFF);
    
    packet.insert(packet.end(), payload.begin(), payload.end());
    
    sendto(sess->udp_sock, (const char*)packet.data(), (int)packet.size(), 0, (sockaddr*)&sess->relay_addr, sizeof(sess->relay_addr));
}

void handle_udp_relay_read(UdpSession* sess) {
    if (sess->state == UdpSession::CLOSED) return;
    
    char buf[4096];
    sockaddr_in from;
    int from_len = sizeof(from);
    int r = recvfrom(sess->udp_sock, buf, sizeof(buf), 0, (sockaddr*)&from, &from_len);
    
    if (r > 10) { // Min header size is 10 (IPv4)
        sess->last_active = GetTickCount64();
        
        // Parse SOCKS5 Header
        // RSV(2) FRAG(1) ATYP(1)
        if (buf[0] != 0 || buf[1] != 0) return;
        if (buf[2] != 0) return; // We don't support fragmentation reassembly here
        
        int header_len = 0;
        uint8_t atyp = buf[3];
        
        if (atyp == 0x01) { // IPv4
            header_len = 10;
        } else if (atyp == 0x03) { // Domain
            uint8_t domain_len = buf[4];
            header_len = 5 + domain_len + 2;
        } else if (atyp == 0x04) { // IPv6
            header_len = 22;
        } else {
            return;
        }
        
        if (r <= header_len) return;
        
        // Payload
        uint8_t* payload = (uint8_t*)(buf + header_len);
        int payload_len = r - header_len;
        
        // Debug: Log DNS responses from the proxy
        if (sess->dst_port == htons(53)) {
            log_dns_packet(payload, payload_len);
        }

        // Construct Reply to Tap
        // We use the session's info to reconstruct the IP packet.
        // Src IP = Session Dst IP (e.g. 8.8.8.8)
        // Dst IP = Session Src IP (e.g. 192.168.1.X)
        
        uint8_t frame[2048];
        if (14 + 20 + 8 + payload_len > 2048) return;

        memcpy(frame, HOST_MAC, 6);
        memcpy(frame + 6, TapDriver::TAP_MAC, 6);
        *(uint16_t*)(frame + 12) = htons(0x0800);

        uint8_t* ip = frame + 14;
        uint8_t* udp_hdr = ip + 20;
        
        // IPv4 Header
        memset(ip, 0, 20);
        ip[0] = 0x45; ip[9] = 17; ip[8] = 64;
        *(uint16_t*)(ip + 2) = htons((uint16_t)(20 + 8 + payload_len));
        *(uint32_t*)(ip + 12) = sess->src_ip; // Dst IP = Client
        *(uint32_t*)(ip + 16) = sess->dst_ip; // Src IP = Server
        *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

        // UDP Header
        *(uint16_t*)(udp_hdr + 0) = sess->src_port; // Dst Port = Client Port
        *(uint16_t*)(udp_hdr + 2) = sess->dst_port; // Src Port = Server Port
        *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + payload_len));
        *(uint16_t*)(udp_hdr + 6) = 0;
        memcpy(udp_hdr + 8, payload, payload_len);

        TapDriver::instance().send_async(frame, 14 + 20 + 8 + payload_len);
    } else if (r == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
             close_udp_session_internal(sess);
        }
    }
}

void handle_socks5_tcp_read(UdpSession* sess) {
    if (sess->state == UdpSession::CLOSED) return;
    
    char buf[512];
    int r = recv(sess->tcp_sock, buf, sizeof(buf), 0);
    
    if (r > 0) {
        if (sess->state == UdpSession::HANDSHAKE_AUTH) {
            // Expect 05 00
            if (r >= 2 && buf[0] == 0x05 && buf[1] == 0x00) {
                // Auth OK. Send UDP ASSOCIATE.
                // Ver(5) Cmd(3) Rsv(0) Atyp(1) DstAddr(4) DstPort(2)
                std::vector<uint8_t> req;
                req.push_back(0x05); 
                req.push_back(0x03); 
                req.push_back(0x00); 
                req.push_back(0x01); // IPv4
                
                // RFC 1928: DST.ADDR/PORT contains the address/port that the CLIENT expects to use.
                // Since we bind to a random port later, we MUST send 0.0.0.0:0 here.
                // Sending the target IP (e.g. 8.8.8.8) here was wrong and caused the proxy 
                // to reject our UDP packets because they came from 127.0.0.1, not 8.8.8.8.
                req.push_back(0); req.push_back(0); req.push_back(0); req.push_back(0); // 0.0.0.0
                req.push_back(0); req.push_back(0); // Port 0

                send(sess->tcp_sock, (const char*)req.data(), (int)req.size(), 0);
                sess->state = UdpSession::HANDSHAKE_ASSOC;
            } else {
                close_udp_session_internal(sess);
            }
        } else if (sess->state == UdpSession::HANDSHAKE_ASSOC) {
            // Expect 05 00 00 ATYP BND.ADDR BND.PORT
            if (r >= 10 && buf[0] == 0x05 && buf[1] == 0x00) {
                // Parse Relay Address
                int addr_len = 0;
                if (buf[3] == 0x01) addr_len = 4;
                else if (buf[3] == 0x04) addr_len = 16;
                else { close_udp_session_internal(sess); return; } // Domain not typically returned here
                
                if (r < 6 + addr_len + 2) { close_udp_session_internal(sess); return; }
                
                // Copy Relay Address
                sess->relay_addr.sin_family = AF_INET;
                // We only support IPv4 relay for now in this struct, 
                // but SOCKS5 might return IPv6. 
                // For simplicity, assume proxy is on localhost IPv4 (127.0.0.1) as configured.
                // But we must use the port returned.
                
                // Note: The BND.ADDR returned by proxy is where we should send UDP.
                // If proxy is 127.0.0.1, it returns 127.0.0.1 or 0.0.0.0.
                if (buf[3] == 0x01) {
                    memcpy(&sess->relay_addr.sin_addr, buf + 4, 4);
                } else {
                    // Fallback: If IPv6, we can't easily use it with sockaddr_in. 
                    // But our PROXY_IP is IPv4. The relay usually binds on same family.
                    // If we get here, something is complex. For now, assume IPv4.
                }
                
                uint16_t port = *(uint16_t*)(buf + 4 + addr_len);
                sess->relay_addr.sin_port = port;
                
                // Create UDP Socket
                sess->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (sess->udp_sock == INVALID_SOCKET) {
                    close_udp_session_internal(sess);
                    return;
                }
                
                // Bind UDP locally
                sockaddr_in local;
                memset(&local, 0, sizeof(local));
                local.sin_family = AF_INET;
                local.sin_addr.S_un.S_addr = INADDR_ANY;
                local.sin_port = 0;
                bind(sess->udp_sock, (sockaddr*)&local, sizeof(local));
                
                u_long mode = 1;
                ioctlsocket(sess->udp_sock, FIONBIO, &mode);
                
                // Register UDP socket to worker
                sess->worker->add_socket(
                    sess->udp_sock,
                    [sess]() { handle_udp_relay_read(sess); },
                    nullptr, 
                    nullptr // Don't auto-close session on UDP close, let control channel handle it
                );
                
                sess->state = UdpSession::ESTABLISHED;
                
                // Flush Pending
                while (!sess->pending_packets.empty()) {
                    send_udp_to_relay(sess, sess->pending_packets.front());
                    sess->pending_packets.pop_front();
                }
            } else {
                close_udp_session_internal(sess);
            }
        }
    } else {
        // TCP Closed -> Session End
        close_udp_session_internal(sess);
    }
}

// Called by Main Thread
void udp_check_timeouts() {
    WorkerPool::instance().for_each_worker([](Worker* w) {
        w->queue_task([]() {
            uint64_t now = GetTickCount64();
            std::vector<UdpSession*> stale_sessions;
            
            for (auto& pair : t_udp_sessions) {
                // Timeout: 60s
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
            // Create New Session
            sess = new UdpSession();
            sess->src_ip = src_ip; sess->dst_ip = dst_ip;
            sess->src_port = src_port; sess->dst_port = dst_port;
            sess->worker = w;
            
            // 1. Create Control TCP Socket
            sess->tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sess->tcp_sock == INVALID_SOCKET) {
                delete sess;
                return;
            }
            u_long mode = 1;
            ioctlsocket(sess->tcp_sock, FIONBIO, &mode);
            
            t_udp_sessions[key] = sess;
            
            // 2. Connect to Proxy
            sockaddr_in proxy_addr;
            memset(&proxy_addr, 0, sizeof(proxy_addr));
            proxy_addr.sin_family = AF_INET;
            
            unsigned int a, b, c, d;
            if (sscanf_s(PROXY_IP, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                proxy_addr.sin_addr.S_un.S_addr = (a) | (b << 8) | (c << 16) | (d << 24);
            } else {
                proxy_addr.sin_addr.S_un.S_addr = 0x0100007F; 
            }
            proxy_addr.sin_port = htons(PROXY_PORT);
            
            // Start Async Connect
            sess->worker->connect_async(
                sess->tcp_sock,
                proxy_addr,
                [sess]() {
                    // TCP Connected. Send SOCKS5 Auth.
                    if (sess->state == UdpSession::CLOSED) return;
                    uint8_t req[] = { 0x05, 0x01, 0x00 };
                    send(sess->tcp_sock, (const char*)req, sizeof(req), 0);
                    sess->state = UdpSession::HANDSHAKE_AUTH;
                    
                    // Switch to read handler for Handshake
                    sess->worker->add_socket(
                        sess->tcp_sock,
                        [sess]() { handle_socks5_tcp_read(sess); },
                        nullptr,
                        [sess]() { close_udp_session_internal(sess); }
                    );
                }
            );
        }
        
        if (sess) {
            sess->last_active = GetTickCount64();
            if (sess->state == UdpSession::ESTABLISHED) {
                send_udp_to_relay(sess, data);
            } else {
                sess->pending_packets.push_back(std::move(data));
            }
        }
    });
}
