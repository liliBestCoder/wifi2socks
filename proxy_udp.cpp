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
    SOCKET tcp_sock; // Control Channel (and Data for DNS-over-TCP)
    SOCKET udp_sock; // Data Channel (Relay) for standard UDP
    
    sockaddr_in relay_addr;
    
    // DNS over TCP specific
    bool is_dns_tcp;
    std::vector<uint8_t> tcp_rx_buffer; // For reassembling TCP streams
    
    enum State { CONNECTING, HANDSHAKE_AUTH, HANDSHAKE_ASSOC, HANDSHAKE_CONNECT, ESTABLISHED, CLOSED } state;
    std::deque<std::vector<uint8_t>> pending_packets;

    UdpSession() : tcp_sock(INVALID_SOCKET), udp_sock(INVALID_SOCKET), worker(NULL), state(CONNECTING), is_dns_tcp(false) { 
        last_active = GetTickCount64(); 
        memset(&relay_addr, 0, sizeof(relay_addr));
        tcp_rx_buffer.reserve(4096);
    }
};

thread_local std::map<UdpKey, UdpSession*> t_udp_sessions;

// Helper to log DNS answers
void log_dns_packet(const uint8_t* payload, int len) {
    if (len < 12) return;
    
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    uint16_t an_count = ntohs(*(uint16_t*)(payload + 6));
    bool is_response = (flags & 0x8000) != 0;

    // printf("[DNS] ID:%04x AN:%d Len:%d\n", ntohs(*(uint16_t*)payload), an_count, len);

    if (!is_response || an_count == 0) return;

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

    printf("[DNS] Received %d Answers via TCP:\n", an_count);

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
        auto worker = sess->worker;
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
    if (sess->state != UdpSession::ESTABLISHED) return;

    if (sess->is_dns_tcp) {
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
            // printf("[DNS-TCP] Sent query via TCP\n");
        }
        
    } else {
        // Standard UDP Associate
        if (sess->udp_sock == INVALID_SOCKET) return;

        std::vector<uint8_t> packet;
        packet.reserve(10 + payload.size());
        
        packet.push_back(0x00); packet.push_back(0x00); // RSV
        packet.push_back(0x00); // FRAG
        packet.push_back(0x01); // ATYP: IPv4
        
        // Use Original Target IP (No hijacking here, we hijack in UDP Assoc)
        // Actually for standard UDP, we just forward to original dst.
        // Unless it's DNS, but DNS is now handled by TCP branch.
        uint32_t target_ip = sess->dst_ip;
        
        packet.push_back(target_ip & 0xFF);
        packet.push_back((target_ip >> 8) & 0xFF);
        packet.push_back((target_ip >> 16) & 0xFF);
        packet.push_back((target_ip >> 24) & 0xFF);
        
        packet.push_back(sess->dst_port & 0xFF);
        packet.push_back((sess->dst_port >> 8) & 0xFF);
        
        packet.insert(packet.end(), payload.begin(), payload.end());
        
        int sent = sendto(sess->udp_sock, (const char*)packet.data(), (int)packet.size(), 0, (sockaddr*)&sess->relay_addr, sizeof(sess->relay_addr));
        if (sent == SOCKET_ERROR) {
            // printf("[UDP] sendto Relay failed! Err: %d\n", WSAGetLastError());
        }
    }
}

void handle_udp_relay_read(UdpSession* sess) {
    if (sess->state == UdpSession::CLOSED) return;
    
    char buf[4096];
    sockaddr_in from;
    int from_len = sizeof(from);
    int r = recvfrom(sess->udp_sock, buf, sizeof(buf), 0, (sockaddr*)&from, &from_len);
    
    if (r > 10) { 
        sess->last_active = GetTickCount64();
        
        if (buf[0] != 0 || buf[1] != 0 || buf[2] != 0) return; 
        
        int header_len = 0;
        uint8_t atyp = buf[3];
        
        if (atyp == 0x01) { header_len = 10; }
        else if (atyp == 0x03) { header_len = 5 + buf[4] + 2; }
        else if (atyp == 0x04) { header_len = 22; }
        else { return; }
        
        if (r <= header_len) return;
        
        uint8_t* payload = (uint8_t*)(buf + header_len);
        int payload_len = r - header_len;
        
        uint8_t frame[2048];
        if (14 + 20 + 8 + payload_len > 2048) return;

        memcpy(frame, HOST_MAC, 6);
        memcpy(frame + 6, TapDriver::TAP_MAC, 6);
        *(uint16_t*)(frame + 12) = htons(0x0800);

        uint8_t* ip = frame + 14;
        uint8_t* udp_hdr = ip + 20;
        
        memset(ip, 0, 20);
        ip[0] = 0x45; ip[9] = 17; ip[8] = 64;
        *(uint16_t*)(ip + 2) = htons((uint16_t)(20 + 8 + payload_len));
        *(uint32_t*)(ip + 12) = sess->src_ip; 
        *(uint32_t*)(ip + 16) = sess->dst_ip; 
        *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

        *(uint16_t*)(udp_hdr + 0) = sess->src_port; 
        *(uint16_t*)(udp_hdr + 2) = sess->dst_port; 
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
    
    char buf[4096];
    int r = recv(sess->tcp_sock, buf, sizeof(buf), 0);
    
    if (r > 0) {
        if (sess->state == UdpSession::HANDSHAKE_AUTH) {
            if (r >= 2 && buf[0] == 0x05 && buf[1] == 0x00) {
                if (sess->is_dns_tcp) {
                    // DNS Mode: Send CONNECT 8.8.8.8:53
                    printf("[SOCKS5-DNS] Auth OK. Connecting to 8.8.8.8:53 via TCP...\n");
                    std::vector<uint8_t> req;
                    req.push_back(0x05); req.push_back(0x01); req.push_back(0x00); req.push_back(0x01);
                    uint32_t ip = 0x08080808; // 8.8.8.8
                    req.push_back(ip & 0xFF); req.push_back((ip >> 8) & 0xFF);
                    req.push_back((ip >> 16) & 0xFF); req.push_back((ip >> 24) & 0xFF);
                    uint16_t port = htons(53);
                    req.push_back(port & 0xFF); req.push_back((port >> 8) & 0xFF);
                    send(sess->tcp_sock, (const char*)req.data(), (int)req.size(), 0);
                    sess->state = UdpSession::HANDSHAKE_CONNECT;
                } else {
                    // Standard UDP Mode: Send UDP ASSOCIATE
                    // printf("[SOCKS5-UDP] Auth OK. Sending UDP ASSOCIATE...\n");
                    uint8_t req[] = { 0x05, 0x03, 0x00, 0x01, 127,0,0,1, 0,0 };
                    send(sess->tcp_sock, (const char*)req, sizeof(req), 0);
                    sess->state = UdpSession::HANDSHAKE_ASSOC;
                }
            } else {
                printf("[SOCKS5] Auth Failed\n");
                close_udp_session_internal(sess);
            }
        } else if (sess->state == UdpSession::HANDSHAKE_ASSOC) {
            // UDP Associate Response
            if (r >= 10 && buf[0] == 0x05 && buf[1] == 0x00) {
                int addr_len = (buf[3] == 0x01) ? 4 : (buf[3] == 0x04 ? 16 : 0);
                if (addr_len == 0 || r < 4 + addr_len + 2) {
                    close_udp_session_internal(sess);
                    return;
                }
                
                sess->relay_addr.sin_family = AF_INET;
                if (buf[3] == 0x01) {
                    uint32_t relay_ip = *(uint32_t*)(buf + 4);
                    if (relay_ip == 0) {
                        unsigned int a, b, c, d;
                        sscanf_s(PROXY_IP, "%u.%u.%u.%u", &a, &b, &c, &d);
                        sess->relay_addr.sin_addr.S_un.S_addr = (a) | (b << 8) | (c << 16) | (d << 24);
                    } else {
                        sess->relay_addr.sin_addr.S_un.S_addr = relay_ip;
                    }
                }
                memcpy(&sess->relay_addr.sin_port, buf + 4 + addr_len, 2);
                
                // Init UDP Socket
                sess->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (sess->udp_sock == INVALID_SOCKET) {
                    close_udp_session_internal(sess);
                    return;
                }
                
                sockaddr_in local;
                memset(&local, 0, sizeof(local));
                local.sin_family = AF_INET;
                unsigned int a, b, c, d;
                sscanf_s("127.0.0.1", "%u.%u.%u.%u", &a, &b, &c, &d);
                local.sin_addr.S_un.S_addr = (a) | (b << 8) | (c << 16) | (d << 24);
                local.sin_port = 0;
                
                if (bind(sess->udp_sock, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
                    close_udp_session_internal(sess);
                    return;
                }
                
                u_long mode = 1;
                ioctlsocket(sess->udp_sock, FIONBIO, &mode);
                
                sess->worker->add_socket(
                    sess->udp_sock,
                    [sess]() { handle_udp_relay_read(sess); },
                    nullptr, nullptr
                );
                
                sess->state = UdpSession::ESTABLISHED;
                // printf("[SOCKS5-UDP] Established. Relay: %d\n", ntohs(sess->relay_addr.sin_port));
                
                while (!sess->pending_packets.empty()) {
                    send_udp_to_relay(sess, sess->pending_packets.front());
                    sess->pending_packets.pop_front();
                }
            } else {
                printf("[SOCKS5-UDP] Assoc Failed\n");
                close_udp_session_internal(sess);
            }
        } else if (sess->state == UdpSession::HANDSHAKE_CONNECT || sess->state == UdpSession::ESTABLISHED) {
            // Processing DNS-over-TCP Data (Response from 8.8.8.8)
            if (sess->is_dns_tcp) {
                if (sess->state == UdpSession::HANDSHAKE_CONNECT) {
                    if (r >= 4 && buf[0] == 0x05 && buf[1] == 0x00) {
                        // printf("[SOCKS5-DNS] TCP Connected to 8.8.8.8\n");
                        sess->state = UdpSession::ESTABLISHED;
                        // Flush pending (convert to TCP format)
                        while (!sess->pending_packets.empty()) {
                            send_udp_to_relay(sess, sess->pending_packets.front());
                            sess->pending_packets.pop_front();
                        }
                    } else {
                        printf("[SOCKS5-DNS] Connect Failed\n");
                        close_udp_session_internal(sess);
                        return;
                    }
                } else {
                    // Data received from 8.8.8.8 (DNS response)
                    // Append to buffer
                    sess->tcp_rx_buffer.insert(sess->tcp_rx_buffer.end(), buf, buf + r);
                    
                    // Process packets in buffer
                    while (sess->tcp_rx_buffer.size() > 2) {
                        uint16_t pkt_len = ntohs(*(uint16_t*)sess->tcp_rx_buffer.data());
                        if (sess->tcp_rx_buffer.size() >= (size_t)2 + pkt_len) {
                            // Full packet extracted
                            uint8_t* payload = sess->tcp_rx_buffer.data() + 2;
                            
                            log_dns_packet(payload, pkt_len);
                            
                            // Send back to Tap as UDP
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
                                *(uint32_t*)(ip + 12) = sess->src_ip; 
                                *(uint32_t*)(ip + 16) = sess->dst_ip; 
                                *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

                                *(uint16_t*)(udp_hdr + 0) = sess->src_port; 
                                *(uint16_t*)(udp_hdr + 2) = sess->dst_port; 
                                *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + pkt_len));
                                *(uint16_t*)(udp_hdr + 6) = 0;
                                memcpy(udp_hdr + 8, payload, pkt_len);

                                TapDriver::instance().send_async(frame, 14 + 20 + 8 + pkt_len);
                            }
                            
                            // Remove processed packet
                            sess->tcp_rx_buffer.erase(sess->tcp_rx_buffer.begin(), sess->tcp_rx_buffer.begin() + 2 + pkt_len);
                        } else {
                            break; // Not enough data
                        }
                    }
                }
            } else {
                // Should not happen for UDP Associate mode (TCP only handles handshake)
                if (r == 0) close_udp_session_internal(sess);
            }
        }
    } else {
        if (r != 0) printf("[ProxyUDP] TCP Error: %d\n", WSAGetLastError());
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
            sess = new UdpSession();
            sess->src_ip = src_ip; sess->dst_ip = dst_ip;
            sess->src_port = src_port; sess->dst_port = dst_port;
            sess->worker = w;
            
            // Check if DNS
            if (dst_port == htons(53)) {
                sess->is_dns_tcp = true;
            }

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
            } else { proxy_addr.sin_addr.S_un.S_addr = 0x0100007F; }
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