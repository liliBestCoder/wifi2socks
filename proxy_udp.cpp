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
    // Unconditional logging for debugging
    if (len < 12) {
        printf("[DNS] Received short packet len=%d\n", len);
        return;
    }
    
    uint16_t id = ntohs(*(uint16_t*)payload);
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    uint16_t qd_count = ntohs(*(uint16_t*)(payload + 4));
    uint16_t an_count = ntohs(*(uint16_t*)(payload + 6));

    printf("[DNS] ID:%04x Flags:%04x QD:%d AN:%d Len:%d\n", id, flags, qd_count, an_count, len);

    bool is_response = (flags & 0x8000) != 0;
    if (!is_response || an_count == 0) return;

    // We only do a rough skip of Queries to get to Answers
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
    
    int sent = sendto(sess->udp_sock, (const char*)packet.data(), (int)packet.size(), 0, (sockaddr*)&sess->relay_addr, sizeof(sess->relay_addr));
    if (sent == SOCKET_ERROR) {
        printf("[UDP] sendto Relay failed! Err: %d\n", WSAGetLastError());
    } else {
        // Debug: Log sending (reduce frequency if needed, but useful now)
        // printf("[UDP] Sent %d bytes to Relay %d.%d.%d.%d:%d\n", 
        //    sent,
        //    sess->relay_addr.sin_addr.S_un.S_un_b.s_b1,
        //    sess->relay_addr.sin_addr.S_un.S_un_b.s_b2,
        //    sess->relay_addr.sin_addr.S_un.S_un_b.s_b3,
        //    sess->relay_addr.sin_addr.S_un.S_un_b.s_b4,
        //    ntohs(sess->relay_addr.sin_port));
    }
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
             printf("[UDP] recvfrom error: %d\n", WSAGetLastError());
             close_udp_session_internal(sess);
        }
    }
}

void handle_socks5_tcp_read(UdpSession* sess) {
    if (sess->state == UdpSession::CLOSED) return;
    
    char buf[512];
    int r = recv(sess->tcp_sock, buf, sizeof(buf), 0);
    
    if (r > 0) {
        // Debug: Log handshake progress
        // printf("[SOCKS5-UDP] State: %d, Recv: %d bytes\n", sess->state, r);
        
        if (sess->state == UdpSession::HANDSHAKE_AUTH) {
            // Expect 05 00
            if (r >= 2 && buf[0] == 0x05 && buf[1] == 0x00) {
                printf("[SOCKS5-UDP] Auth OK. Sending UDP ASSOCIATE...\n");
                
                // Auth OK. Send UDP ASSOCIATE.
                // Ver(5) Cmd(3) Rsv(0) Atyp(1) DstAddr(4) DstPort(2)
                // Use 0.0.0.0:0 to bind to any client address
                uint8_t req[] = { 0x05, 0x03, 0x00, 0x01, 0,0,0,0, 0,0 };
                send(sess->tcp_sock, (const char*)req, sizeof(req), 0);
                sess->state = UdpSession::HANDSHAKE_ASSOC;
            } else {
                printf("[SOCKS5-UDP] Auth Failed! Hex: %02X %02X\n", (uint8_t)buf[0], (uint8_t)buf[1]);
                close_udp_session_internal(sess);
            }
        } else if (sess->state == UdpSession::HANDSHAKE_ASSOC) {
            // Expect 05 00 00 ATYP BND.ADDR BND.PORT
            // Note: r >= 10 checks minimum size for IPv4 address response
            if (r >= 10 && buf[0] == 0x05 && buf[1] == 0x00) {
                // Parse Relay Address
                int addr_len = 0;
                if (buf[3] == 0x01) addr_len = 4;
                else if (buf[3] == 0x04) addr_len = 16;
                else { 
                    printf("[SOCKS5-UDP] Invalid Address Type: %d\n", buf[3]);
                    close_udp_session_internal(sess); 
                    return; 
                } 
                
                // Basic length safety check
                // Header (4) + Addr + Port (2)
                if (r < 4 + addr_len + 2) { 
                    printf("[SOCKS5-UDP] Packet too short for address type. Len: %d, Expected: %d\n", r, 4 + addr_len + 2);
                    close_udp_session_internal(sess); 
                    return; 
                }
                
                sess->relay_addr.sin_family = AF_INET;
                
                if (buf[3] == 0x01) { // IPv4
                    uint32_t relay_ip = *(uint32_t*)(buf + 4);
                    // Check if Relay IP is 0.0.0.0, if so, use Proxy IP (127.0.0.1)
                    if (relay_ip == 0) {
                        unsigned int a, b, c, d;
                        if (sscanf_s(PROXY_IP, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                             sess->relay_addr.sin_addr.S_un.S_addr = (a) | (b << 8) | (c << 16) | (d << 24);
                        } else {
                             sess->relay_addr.sin_addr.S_un.S_addr = 0x0100007F; 
                        }
                        printf("[SOCKS5-UDP] Relay IP was 0.0.0.0, patched to Local Proxy IP.\n");
                    } else {
                        sess->relay_addr.sin_addr.S_un.S_addr = relay_ip;
                    }
                } else {
                    // IPv6 unsupported fallback logic or just error log
                    printf("[SOCKS5-UDP] IPv6 Relay Address received (unsupported path), trying IPv4 fallback interpretation...\n");
                }
                
                // Safe copy for port (Network Order)
                memcpy(&sess->relay_addr.sin_port, buf + 4 + addr_len, 2);
                
                printf("[SOCKS5] UDP Assoc OK. Relay: %d.%d.%d.%d:%d\n", 
                    sess->relay_addr.sin_addr.S_un.S_un_b.s_b1,
                    sess->relay_addr.sin_addr.S_un.S_un_b.s_b2,
                    sess->relay_addr.sin_addr.S_un.S_un_b.s_b3,
                    sess->relay_addr.sin_addr.S_un.S_un_b.s_b4,
                    ntohs(sess->relay_addr.sin_port));
                fflush(stdout); // Force print
                
                // Create UDP Socket
                sess->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (sess->udp_sock == INVALID_SOCKET) {
                    printf("[SOCKS5-UDP] Failed to create UDP socket\n");
                    close_udp_session_internal(sess);
                    return;
                }
                
                // Bind UDP locally
                sockaddr_in local;
                memset(&local, 0, sizeof(local));
                local.sin_family = AF_INET;
                local.sin_addr.S_un.S_addr = INADDR_ANY;
                local.sin_port = 0;
                if (bind(sess->udp_sock, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
                    printf("[SOCKS5-UDP] UDP Bind Failed: %d\n", WSAGetLastError());
                    close_udp_session_internal(sess);
                    return;
                }
                
                u_long mode = 1;
                ioctlsocket(sess->udp_sock, FIONBIO, &mode);
                
                // Register UDP socket to worker
                sess->worker->add_socket(
                    sess->udp_sock,
                    [sess]() { handle_udp_relay_read(sess); },
                    nullptr, 
                    nullptr 
                );
                
                sess->state = UdpSession::ESTABLISHED;
                
                // Flush Pending
                while (!sess->pending_packets.empty()) {
                    send_udp_to_relay(sess, sess->pending_packets.front());
                    sess->pending_packets.pop_front();
                }
            } else {
                printf("[SOCKS5-UDP] Assoc Failed! Rep: %02X %02X Len: %d\n", (uint8_t)buf[0], (uint8_t)buf[1], r);
                close_udp_session_internal(sess);
            }
        }
    } else {
        // TCP Closed or Error
        if (r == 0) {
             // printf("[SOCKS5-UDP] TCP Control Channel Closed Gracefully.\n");
        } else {
             printf("[SOCKS5-UDP] TCP Control Read Error: %d\n", WSAGetLastError());
        }
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