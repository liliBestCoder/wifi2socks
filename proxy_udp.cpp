#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include "winpkfilter_driver.h"
#include "proxy_udp.h"
#include "worker.h"
#include "app_config.h"
#include "traffic_manager.h"
#include "lwip_handler.h"
#include "nat_table.h"
#include "geo_checker.h"
#include "rule_manager.h"
#include "dns_cache.h"
#include <map>
#include <vector>
#include <deque>
#include <algorithm>
#include <atomic>
#include <cstring>

// Include LwIP ethernet protocol headers
#include "lwip/prot/ethernet.h"

// Global IP ID counter for outbound UDP
static std::atomic<uint16_t> g_udp_ip_id(1000);

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
    
    uint16_t flags = ::ntohs(*(uint16_t*)(payload + 2));
    uint16_t an_count = ::ntohs(*(uint16_t*)(payload + 6));
    
    if ((flags & 0x8000) && an_count > 0) { 
        uint16_t qd_count = ::ntohs(*(uint16_t*)(payload + 4));
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
            
            uint16_t type = ::ntohs(*(uint16_t*)(payload+pos));
            uint32_t ttl = ::ntohl(*(uint32_t*)(payload+pos+4));
            uint16_t rdlen = ::ntohs(*(uint16_t*)(payload+pos+8));
            pos += 10;
            
            if (type == 1 && rdlen == 4 && pos + 4 <= len) { 
                uint32_t ip = *(uint32_t*)(payload + pos);
                LOG_INFO("[DNS] %s -> %d.%d.%d.%d (TTL: %d) via %s", 
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

// Helper to calculate UDP Checksum (Pseudo-header + Payload)
uint16_t calculate_udp_checksum(uint32_t src_ip, uint32_t dst_ip, uint8_t* udp_pkt, int udp_len) {
    uint32_t sum = 0;
    sum += (src_ip & 0xFFFF);
    sum += (src_ip >> 16);
    sum += (dst_ip & 0xFFFF);
    sum += (dst_ip >> 16);
    sum += ::htons(17);
    sum += ::htons((uint16_t)udp_len);
    const uint16_t* ptr = (const uint16_t*)udp_pkt;
    int len = udp_len;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len > 0) { sum += (uint16_t)(*(const uint8_t*)ptr); }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// Inject packet back to client
void inject_udp_reply(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len) {
    if (!g_winpkfilter_driver) return;

    NatEntry entry = NatTable::instance().get(dst_ip, ::ntohs(dst_port));
    if (entry.original_dst_ip == 0) return;

    uint8_t packet[2048];
    int eth_len = sizeof(struct eth_hdr);
    if (eth_len + 20 + 8 + len > sizeof(packet)) return;

    struct eth_hdr* eth = (struct eth_hdr*)packet;
    uint8_t* ip_hdr = packet + eth_len;
    uint8_t* udp_hdr = ip_hdr + 20;

    // Ethernet
    memcpy(&eth->dest, entry.src_mac, 6);
    memcpy(&eth->src, entry.dst_mac, 6);
    eth->type = htons(ETHTYPE_IP);

    // IP
    memset(ip_hdr, 0, 20);
    ip_hdr[0] = 0x45; ip_hdr[9] = 17; ip_hdr[8] = 64;
    *(uint16_t*)(ip_hdr + 2) = ::htons((uint16_t)(20 + 8 + len));
    *(uint16_t*)(ip_hdr + 4) = ::htons(g_udp_ip_id.fetch_add(1));
    *(uint32_t*)(ip_hdr + 12) = src_ip; 
    *(uint32_t*)(ip_hdr + 16) = dst_ip; 
    *(uint16_t*)(ip_hdr + 10) = ip_chksum_simple(ip_hdr, 20);

    // UDP
    *(uint16_t*)(udp_hdr + 0) = src_port; 
    *(uint16_t*)(udp_hdr + 2) = dst_port; 
    *(uint16_t*)(udp_hdr + 4) = ::htons((uint16_t)(8 + len));
    *(uint16_t*)(udp_hdr + 6) = 0;
    memcpy(udp_hdr + 8, payload, len);
    *(uint16_t*)(udp_hdr + 6) = calculate_udp_checksum(src_ip, dst_ip, udp_hdr, 8 + len);

    g_winpkfilter_driver->send_to_adapter((const char*)packet, eth_len + 20 + 8 + len);
}

void handle_udp_direct_read(UdpSession* sess, char* data, int len, sockaddr_in* addr) {
    if (sess->state == UdpSession::CLOSED) return; 
    if (len > 0 && data && addr) {
        TrafficManager::instance().report_proxy_rx(len, true);
        inject_udp_reply(sess->original_dst_ip, sess->src_ip, sess->original_dst_port, sess->src_port, (const uint8_t*)data, len);
        
        if (sess->original_dst_port == ::htons(53)) {
            parse_and_log_dns_response((const uint8_t*)data, len, "Direct (UDP)");
        }
        sess->last_active = GetTickCount64();
    }
}

void send_dns_response(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t id, const std::string& domain, uint32_t ip_addr) {
    std::vector<uint8_t> resp;
    resp.push_back(id & 0xFF); resp.push_back((id >> 8) & 0xFF);
    resp.push_back(0x81); resp.push_back(0x80); 
    resp.push_back(0x00); resp.push_back(0x01); 
    resp.push_back(0x00); resp.push_back(0x01); 
    resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x00); resp.push_back(0x00);
    size_t pos = 0;
    while (pos < domain.length()) {
        size_t next_dot = domain.find('.', pos);
        std::string label = (next_dot == std::string::npos) ? domain.substr(pos) : domain.substr(pos, next_dot - pos);
        pos = (next_dot == std::string::npos) ? domain.length() : next_dot + 1;
        resp.push_back((uint8_t)(std::min)((size_t)63, label.length()));
        for (size_t i=0; i<(std::min)((size_t)63, label.length()); ++i) resp.push_back(label[i]);
    }
    resp.push_back(0); 
    resp.push_back(0x00); resp.push_back(0x01); resp.push_back(0x00); resp.push_back(0x01);
    resp.push_back(0xC0); resp.push_back(0x0C); resp.push_back(0x00); resp.push_back(0x01);
    resp.push_back(0x00); resp.push_back(0x01); resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x00); resp.push_back(0x3C); resp.push_back(0x00); resp.push_back(0x04);
    resp.push_back(ip_addr & 0xFF); resp.push_back((ip_addr >> 8) & 0xFF);
    resp.push_back((ip_addr >> 16) & 0xFF); resp.push_back((ip_addr >> 24) & 0xFF);
    
    inject_udp_reply(dst_ip, src_ip, dst_port, src_port, resp.data(), (int)resp.size());
}

void send_dns_empty_response(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t id, const uint8_t* query_payload, int query_len) {
    if (query_len > 1024) return;
    std::vector<uint8_t> resp;
    resp.push_back(id & 0xFF); resp.push_back((id >> 8) & 0xFF);
    resp.push_back(0x81); resp.push_back(0x80); 
    resp.push_back(0x00); resp.push_back(0x01); 
    resp.push_back(0x00); resp.push_back(0x00); 
    resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x00); resp.push_back(0x00);
    if (query_len > 12) resp.insert(resp.end(), query_payload + 12, query_payload + query_len);
    inject_udp_reply(dst_ip, src_ip, dst_port, src_port, resp.data(), (int)resp.size());
}

void send_dns_over_tcp(UdpSession* sess, const std::vector<uint8_t>& payload) {
    if (sess->state != UdpSession::ESTABLISHED) return;
    uint16_t len = ::htons((uint16_t)payload.size());
    std::vector<uint8_t> tcp_pkt;
    tcp_pkt.resize(2 + payload.size());
    memcpy(tcp_pkt.data(), &len, 2);
    memcpy(tcp_pkt.data() + 2, payload.data(), payload.size());
    int sent = send(sess->tcp_sock, (const char*)tcp_pkt.data(), (int)tcp_pkt.size(), 0);
    if (sent == SOCKET_ERROR) close_udp_session_internal(sess);
    else TrafficManager::instance().report_proxy_tx(sent, false);
}

void handle_socks5_tcp_read(UdpSession* sess) {
    if (sess->state == UdpSession::CLOSED) return; 
    char buf[4096];
    int r = recv(sess->tcp_sock, buf, sizeof(buf), 0);
    if (r > 0) {
        TrafficManager::instance().report_proxy_rx(r, false);
        if (sess->state == UdpSession::HANDSHAKE_AUTH) {
            if (r >= 2 && buf[0] == 0x05 && buf[1] == 0x00) {
                std::vector<uint8_t> req = {0x05, 0x01, 0x00, 0x01};
                uint32_t ip = sess->proxy_target_ip; 
                req.push_back(ip & 0xFF); req.push_back((ip >> 8) & 0xFF);
                req.push_back((ip >> 16) & 0xFF); req.push_back((ip >> 24) & 0xFF);
                uint16_t port = sess->proxy_target_port;
                req.push_back(port & 0xFF); req.push_back((port >> 8) & 0xFF);
                int sent = send(sess->tcp_sock, (const char*)req.data(), (int)req.size(), 0);
                if (sent > 0) TrafficManager::instance().report_proxy_tx(sent, false);
                sess->state = UdpSession::HANDSHAKE_CONNECT;
            } else close_udp_session_internal(sess);
        } else if (sess->state == UdpSession::HANDSHAKE_CONNECT) {
            if (r >= 4 && buf[0] == 0x05 && buf[1] == 0x00) {
                sess->state = UdpSession::ESTABLISHED;
                int header_len = (buf[3] == 0x01) ? 10 : ((buf[3] == 0x04) ? 22 : (7 + buf[4]));
                if (r > header_len) sess->tcp_rx_buffer.insert(sess->tcp_rx_buffer.end(), buf + header_len, buf + r);
                while (!sess->pending_packets.empty()) {
                    send_dns_over_tcp(sess, sess->pending_packets.front());
                    sess->pending_packets.pop_front();
                }
            } else close_udp_session_internal(sess);
        } else if (sess->state == UdpSession::ESTABLISHED) {
            sess->tcp_rx_buffer.insert(sess->tcp_rx_buffer.end(), (uint8_t*)buf, (uint8_t*)buf + r);
            while (sess->tcp_rx_buffer.size() > 2) {
                uint16_t pkt_len = ::ntohs(*(uint16_t*)sess->tcp_rx_buffer.data());
                if (sess->tcp_rx_buffer.size() >= (size_t)2 + pkt_len) {
                    uint8_t* payload = sess->tcp_rx_buffer.data() + 2;
                    uint16_t id = *(uint16_t*)payload;
                    parse_and_log_dns_response(payload, pkt_len, "Proxy (TCP)");
                    std::string target_domain = sess->original_domain_with_suffix.empty() ? sess->clean_domain : sess->original_domain_with_suffix;
                    
                    // Rewrite IP response (simplified: just taking first A record)
                    int pos = 12;
                    uint16_t qd_count = ntohs(*(uint16_t*)(payload + 4));
                    for(int i=0; i<qd_count; i++) {
                        while(pos < pkt_len) {
                            uint8_t n = payload[pos];
                            if(n==0) { pos++; break; }
                            if((n&0xC0)==0xC0) { pos+=2; break; }
                            pos += n+1;
                        }
                        pos += 4;
                    }
                    uint16_t an_count = ntohs(*(uint16_t*)(payload + 6));
                    for(int i=0; i<an_count; i++) {
                        while(pos < pkt_len) {
                            uint8_t n = payload[pos];
                            if(n==0) { pos++; break; }
                            if((n&0xC0)==0xC0) { pos+=2; break; }
                            pos += n+1;
                        }
                        if(pos+10 > pkt_len) break;
                        uint16_t type = ntohs(*(uint16_t*)(payload+pos));
                        uint16_t rdlen = ntohs(*(uint16_t*)(payload+pos+8));
                        if (type == 1 && rdlen == 4 && pos + 14 <= pkt_len) {
                            uint32_t ip = *(uint32_t*)(payload + pos + 10);
                            send_dns_response(sess->src_ip, sess->original_dst_ip, sess->src_port, sess->original_dst_port, id, target_domain, ip);
                            break;
                        }
                        pos += 10 + rdlen;
                    }
                    sess->tcp_rx_buffer.erase(sess->tcp_rx_buffer.begin(), sess->tcp_rx_buffer.begin() + 2 + pkt_len);
                } else break; 
            }
        }
    } else close_udp_session_internal(sess);
}

std::string parse_dns_qname(const uint8_t* payload, int len, int* qname_len) {
    if (len < 12) return "";
    int pos = 12;
    std::string domain;
    while (pos < len) {
        uint8_t n = payload[pos];
        if (n == 0) { pos++; break; }
        if ((n & 0xC0) == 0xC0) return ""; 
        if (pos + n + 1 > len) return "";
        if (!domain.empty()) domain += ".";
        domain.append((char*)(payload + pos + 1), n);
        pos += n + 1;
    }
    if (qname_len) *qname_len = pos - 12;
    return domain;
}

std::vector<uint8_t> build_dns_query(uint16_t id, const std::string& domain) {
    std::vector<uint8_t> req;
    req.push_back(id & 0xFF); req.push_back((id >> 8) & 0xFF);
    req.push_back(0x01); req.push_back(0x00); req.push_back(0x00); req.push_back(0x01);
    req.push_back(0x00); req.push_back(0x00); req.push_back(0x00); req.push_back(0x00); req.push_back(0x00); req.push_back(0x00); 
    size_t pos = 0;
    while (pos < domain.length()) {
        size_t next_dot = domain.find('.', pos);
        std::string label = (next_dot == std::string::npos) ? domain.substr(pos) : domain.substr(pos, next_dot - pos);
        pos = (next_dot == std::string::npos) ? domain.length() : next_dot + 1;
        req.push_back((uint8_t)(std::min)((size_t)63, label.length()));
        for (char c : label) req.push_back(c);
    }
    req.push_back(0); req.push_back(0x00); req.push_back(0x01); req.push_back(0x00); req.push_back(0x01);
    return req;
}

void udp_check_timeouts() {
    WorkerPool::instance().for_each_worker([](Worker* w) {
        w->queue_task([]() {
            uint64_t now = GetTickCount64();
            std::vector<UdpSession*> stale;
            for (auto& pair : t_udp_sessions) if (now - pair.second->last_active > 300000) stale.push_back(pair.second);
            for (auto* sess : stale) close_udp_session_internal(sess);
        });
    });
}

void forward_udp_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len) {
    uint32_t hash = src_port ^ dst_port ^ src_ip ^ dst_ip;
    Worker* w = WorkerPool::instance().get_worker(hash);
    if (!w) w = WorkerPool::instance().get_next_worker();
    std::vector<uint8_t> data(payload, payload + len);
    w->queue_task([src_ip, dst_ip, src_port, dst_port, data = std::move(data), w]() {
        UdpKey key = { src_ip, dst_ip, src_port, dst_port };
        UdpSession* sess = nullptr;
        auto it = t_udp_sessions.find(key);
        if (it != t_udp_sessions.end()) sess = it->second;
        else {
            sess = new UdpSession();
            sess->src_ip = src_ip; sess->original_dst_ip = dst_ip; 
            sess->src_port = src_port; sess->original_dst_port = dst_port;
            sess->worker = w;
            sess->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sess->udp_sock == INVALID_SOCKET) { delete sess; return; }
            sockaddr_in local; memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET; local.sin_addr.S_un.S_addr = INADDR_ANY; local.sin_port = 0;
            bind(sess->udp_sock, (sockaddr*)&local, sizeof(local));
            u_long mode = 1; ioctlsocket(sess->udp_sock, FIONBIO, &mode);
            t_udp_sessions[key] = sess;
            sess->worker->add_socket(sess->udp_sock,
                [sess](char* data, int len, sockaddr_in* addr) { handle_udp_direct_read(sess, data, len, addr); },
                nullptr, [sess]() { close_udp_session_internal(sess); }, true);
            sess->state = UdpSession::ESTABLISHED;
        }
        if (sess && sess->state != UdpSession::CLOSED) {
            sess->last_active = GetTickCount64();
            sockaddr_in dest; memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET; dest.sin_addr.S_un.S_addr = dst_ip; dest.sin_port = dst_port; 
            int sent = sendto(sess->udp_sock, (const char*)data.data(), (int)data.size(), 0, (sockaddr*)&dest, sizeof(dest));
            if (sent > 0) TrafficManager::instance().report_proxy_tx(sent, true);
        }
    });
}

void handle_udp_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len) {
    uint16_t dport_h = ::ntohs(dst_port);
    if (dport_h == 5353 || dport_h == 5355 || dport_h == 137 || dport_h == 138 || dport_h == 1900) return;
    RouteAction ip_action = RuleManager::instance().match_ip(::ntohl(dst_ip));
    if (ip_action == RouteAction::BLOCK) return;
    if (ip_action == RouteAction::DIRECT) {
        forward_udp_packet(src_ip, dst_ip, src_port, dst_port, payload, len);
        return;
    }
    if (dst_port == ::htons(443)) {
        if (GeoChecker::instance().is_cn_ip(::ntohl(dst_ip))) forward_udp_packet(src_ip, dst_ip, src_port, dst_port, payload, len);
        return;
    }
    if (dst_port == ::htons(53)) {
        int qname_len = 0;
        std::string full_domain = parse_dns_qname(payload, len, &qname_len);
        if (!full_domain.empty()) {
            if (full_domain.find("msftncsi") != std::string::npos || full_domain.find("msftconnecttest") != std::string::npos || full_domain.find("connectivitycheck") != std::string::npos) {
                send_dns_response(src_ip, dst_ip, src_port, dst_port, *(uint16_t*)payload, full_domain, inet_addr("131.107.255.255"));
                return;
            }
            RouteAction dom_action = RuleManager::instance().match_domain(full_domain);
            if (dom_action == RouteAction::BLOCK) {
                send_dns_empty_response(src_ip, dst_ip, src_port, dst_port, *(uint16_t*)payload, payload, len);
                return;
            }
            if (12 + qname_len + 2 <= len) {
                if (::ntohs(*(uint16_t*)(payload + 12 + qname_len)) == 28) {
                    send_dns_empty_response(src_ip, dst_ip, src_port, dst_port, *(uint16_t*)payload, payload, len);
                    return; 
                }
            }
            std::string clean_domain = full_domain;
            std::string temp = full_domain;
            std::transform(temp.begin(), temp.end(), temp.begin(), [](unsigned char c){ return std::tolower(c); });
            const char* suffixes[] = { ".mshome.net", ".lan", ".local", ".localdomain" };
            bool stripped = false;
            for (const char* suf : suffixes) {
                size_t suflen = strlen(suf);
                if (temp.length() > suflen && temp.compare(temp.length() - suflen, suflen, suf) == 0) {
                    clean_domain = full_domain.substr(0, full_domain.length() - suflen);
                    stripped = true; break; 
                }
            }
            uint32_t cached_ip = DnsCache::instance().get(clean_domain);
            if (cached_ip != 0) {
                send_dns_response(src_ip, dst_ip, src_port, dst_port, *(uint16_t*)payload, full_domain, cached_ip);
                return;
            }
            bool domestic = (dom_action == RouteAction::DIRECT) || (dom_action == RouteAction::PASS && (GeoChecker::instance().is_cn_domain(clean_domain) || GeoChecker::instance().is_tencent_domain(clean_domain)));
            if (domestic) {
                uint32_t ali_dns = inet_addr("223.5.5.5");
                forward_udp_packet(src_ip, ali_dns, src_port, dst_port, payload, len);
                return;
            } else { 
                uint32_t google_dns = inet_addr("8.8.8.8");
                std::vector<uint8_t> query;
                const uint8_t* p_data = payload; int p_len = len;
                if (stripped) { query = build_dns_query(*(uint16_t*)payload, clean_domain); p_data = query.data(); p_len = (int)query.size(); }
                uint32_t hash = src_port ^ dst_port ^ src_ip ^ dst_ip;
                Worker* w = WorkerPool::instance().get_worker(hash);
                if (!w) w = WorkerPool::instance().get_next_worker();
                std::vector<uint8_t> data(p_data, p_data + p_len);
                w->queue_task([src_ip, dst_ip, src_port, dst_port, google_dns, data = std::move(data), w, full_domain, clean_domain]() {
                    UdpKey key = { src_ip, dst_ip, src_port, dst_port };
                    UdpSession* sess = nullptr;
                    auto it = t_udp_sessions.find(key);
                    if (it == t_udp_sessions.end()) {
                        sess = new UdpSession();
                        sess->src_ip = src_ip; sess->original_dst_ip = dst_ip; 
                        sess->src_port = src_port; sess->original_dst_port = dst_port;
                        sess->proxy_target_ip = google_dns; sess->proxy_target_port = ::htons(53);
                        sess->worker = w; sess->is_dns_tcp = true;
                        sess->original_domain_with_suffix = full_domain; sess->clean_domain = clean_domain;
                        sess->tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
                        if (sess->tcp_sock == INVALID_SOCKET) { delete sess; return; }
                        u_long mode = 1; ioctlsocket(sess->tcp_sock, FIONBIO, &mode);
                        t_udp_sessions[key] = sess;
                        sockaddr_in proxy; memset(&proxy, 0, sizeof(proxy));
                        proxy.sin_family = AF_INET; inet_pton(AF_INET, g_config.proxy_ip.c_str(), &proxy.sin_addr); proxy.sin_port = ::htons(g_config.proxy_port);
                        sess->worker->connect_async(sess->tcp_sock, proxy, [sess]() {
                            if (sess->state == UdpSession::CLOSED) return;
                            uint8_t req[] = { 0x05, 0x01, 0x00 };
                            send(sess->tcp_sock, (const char*)req, sizeof(req), 0);
                            sess->state = UdpSession::HANDSHAKE_AUTH;
                            sess->worker->add_socket(sess->tcp_sock, [sess](char*, int, sockaddr_in*) { handle_socks5_tcp_read(sess); }, nullptr, [sess]() { close_udp_session_internal(sess); }, false);
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
    forward_udp_packet(src_ip, dst_ip, src_port, dst_port, payload, len);
}