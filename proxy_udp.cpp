#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "proxy_udp.h"
#include "worker.h"
#include "logger.h"
#include "rule_manager.h"
#include "geo_checker.h"
#include "app_config.h"
#include "traffic_manager.h"
#include "app_listener.h"
#include "proxy_tcp.h"
#include "dns_over_tcp_proxy.h"
#include "dns_cache.h"

#include <unordered_map>
#include <map>
#include <mutex>
#include <memory>
#include <vector>
#include <string>
#include <ws2tcpip.h>

// Struct to hold DNS response details
struct DnsResponse {
    std::string qname;
    uint16_t qtype;
    uint16_t rcode;
    std::vector<std::string> addresses;
    bool parse_error = false;
};

// Function to parse a raw DNS response packet
DnsResponse parse_dns_response(const char* data, int len) {
    DnsResponse res;
    if (len < 12) {
        res.parse_error = true;
        return res;
    }

    // --- Parse Header ---
    res.rcode = ntohs(*(uint16_t*)(data + 2)) & 0x000F;
    uint16_t qdcount = ntohs(*(uint16_t*)(data + 4));
    uint16_t ancount = ntohs(*(uint16_t*)(data + 6));
    
    if (qdcount != 1) { // We only handle single-question responses
        // res.parse_error = true; 
        // Allow it, but parsing might be limited
    }

    const char* p = data + 12; // Start of question section

    // --- Parse Question Section ---
    std::string qname;
    // Only parse the first question
    if (qdcount > 0) {
        while (*p != 0) {
            if ((unsigned char)*p >= 192) { // It's a pointer 0xC0xx
                // Pointer logic not strictly needed for basic parsing of standard responses where qname is inline
                // But for robustness:
                int offset = ((unsigned char)*p & 0x3F) << 8 | (unsigned char)*(p + 1);
                // We don't support pointer jumping back for qname extraction here for simplicity 
                // in this lightweight parser unless needed. 
                // Usually request QNAME is literal labels.
                p += 2;
                break; 
            }
            uint8_t label_len = (uint8_t)*p++;
            if (p + label_len > data + len) {
                res.parse_error = true;
                return res;
            }
            if (!qname.empty()) qname += ".";
            qname.append(p, label_len);
            p += label_len;
        }
        if (*p == 0) p++; // Skip null terminator if not pointer
        res.qname = qname;

        if (p + 4 > data + len) {
            res.parse_error = true;
            return res;
        }
        res.qtype = ntohs(*(uint16_t*)p);
        p += 4; // Skip qtype and qclass
    }

    // --- Parse Answer Section ---
    for (int i = 0; i < ancount; ++i) {
        if (p >= data + len) break;

        // Parse Name (can be a pointer)
        if (((unsigned char)*p & 0xC0) == 0xC0) { // Pointer
            p += 2;
        } else { // Full name
            while (*p != 0) {
                uint8_t label_len = (uint8_t)*p++;
                p += label_len;
            }
            p++;
        }

        if (p + 10 > data + len) break;
        
        uint16_t type = ntohs(*(uint16_t*)p);
        uint16_t data_len = ntohs(*(uint16_t*)(p + 8));
        p += 10;

        if (type == 1 && data_len == 4) { // TYPE A record
            if (p + 4 <= data + len) {
                char ip_str[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, p, ip_str, INET_ADDRSTRLEN)) {
                    res.addresses.push_back(ip_str);
                }
            }
        }
        p += data_len;
    }

    return res;
}

// Helper to build a raw DNS A-record response
// returns vector of bytes
std::vector<char> build_dns_a_response(const char* request_data, int request_len, uint32_t ip_nbo) {
    if (request_len < 12) return {};

    std::vector<char> response;
    response.reserve(request_len + 16); // Header + Q + Answer

    // Copy Request
    response.insert(response.end(), request_data, request_data + request_len);

    // Modify Header
    // 1. Flags (Byte 2 and 3). Set QR=1, RA=1. Keep RD if set.
    // Standard response: 0x8180 (No error)
    uint16_t* flags = (uint16_t*)(response.data() + 2);
    *flags = htons(0x8180); 

    // 2. Answer Count (Byte 6 and 7). Set to 1.
    uint16_t* an_count = (uint16_t*)(response.data() + 6);
    *an_count = htons(1);

    // 3. Authority and Additional counts set to 0
    uint16_t* ns_count = (uint16_t*)(response.data() + 8);
    *ns_count = 0;
    uint16_t* ar_count = (uint16_t*)(response.data() + 10);
    *ar_count = 0;

    // Append Answer Record
    // Name: Pointer to the QNAME at offset 12 (0xC00C)
    // 0xC0 0x0C
    response.push_back((char)0xC0);
    response.push_back((char)0x0C);

    // Type: A (1)
    response.push_back(0); response.push_back(1);
    // Class: IN (1)
    response.push_back(0); response.push_back(1);
    // TTL: 300 seconds (0x0000012C)
    response.push_back(0); response.push_back(0); response.push_back(1); response.push_back(0x2C);
    // RDLENGTH: 4
    response.push_back(0); response.push_back(4);
    // RDATA: IP address (already in network byte order)
    const char* ip_bytes = (const char*)&ip_nbo;
    response.push_back(ip_bytes[0]);
    response.push_back(ip_bytes[1]);
    response.push_back(ip_bytes[2]);
    response.push_back(ip_bytes[3]);

    return response;
}

// Helper to build an empty DNS response (NOERROR, 0 answers)
std::vector<char> build_dns_empty_response(const char* request_data, int request_len) {
    if (request_len < 12) return {};
    std::vector<char> response(request_data, request_data + request_len);
    uint16_t* flags = (uint16_t*)(response.data() + 2);
    *flags = htons(0x8180); // QR=1, RA=1, NOERROR
    *(uint16_t*)(response.data() + 6) = 0; // ANCOUNT
    *(uint16_t*)(response.data() + 8) = 0; // NSCOUNT
    *(uint16_t*)(response.data() + 10) = 0; // ARCOUNT
    return response;
}

// A manager to handle all UDP proxy operations with proper flow isolation.
class UdpProxyManager {
public:
    UdpProxyManager() : m_last_cleanup(GetTickCount64()) {}

    void initialize() {}

    void shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto const& [key, session] : m_sessions) {
            if (session.sock != INVALID_SOCKET) {
                WorkerPool::instance().remove_socket(session.sock);
                closesocket(session.sock);
            }
        }
        m_sessions.clear();
        m_socket_to_flow.clear();
        LOG_INFO("[UDP] Shutdown complete.");
    }

    // Flow key representing a unique 4-tuple UDP session
    struct FlowKey {
        uint32_t src_ip;
        uint16_t src_port;
        uint32_t dst_ip;
        uint16_t dst_port;

        bool operator<(const FlowKey& o) const {
            if (src_ip != o.src_ip) return src_ip < o.src_ip;
            if (src_port != o.src_port) return src_port < o.src_port;
            if (dst_ip != o.dst_ip) return dst_ip < o.dst_ip;
            return dst_port < o.dst_port;
        }
    };

    struct Session {
        SOCKET sock;
        sockaddr_in client_addr;
        uint64_t last_access;
    };

    void handle_data(SOCKET listener_socket, const char* data, int len, const sockaddr_in* client_addr, const OriginalDestination* dest) {
        uint16_t dport = ntohs(dest->port);
        bool is_dns = (dport == 53);

        // --- 1. DNS Interception ---
        if (is_dns) {
            uint16_t qtype = 0;
            std::string domain = parse_dns_query_domain(data, len, &qtype);
            if (!domain.empty()) {
                if (qtype == 28) { // AAAA Record (IPv6)
                    LOG_DEBUG("[DNS] Blocking AAAA query for '%s' to force IPv4 fallback", domain.c_str());
                    std::vector<char> resp = build_dns_empty_response(data, len);
                    if (!resp.empty()) {
                        sendto(listener_socket, resp.data(), (int)resp.size(), 0, (const sockaddr*)client_addr, sizeof(*client_addr));
                    }
                    return;
                }

                uint32_t cached_ip = DnsCache::instance().get(domain);
                if (cached_ip != 0) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &cached_ip, ip_str, INET_ADDRSTRLEN);
                    LOG_DEBUG("[DNS] Cache Hit for '%s' -> %s", domain.c_str(), ip_str);

                    std::vector<char> resp = build_dns_a_response(data, len, cached_ip);
                    if (!resp.empty()) {
                        sendto(listener_socket, resp.data(), (int)resp.size(), 0, (const sockaddr*)client_addr, sizeof(*client_addr));
                    }
                    return;
                }

                RouteAction rule = RuleManager::instance().match_domain(domain);
                bool is_cn = GeoChecker::instance().is_cn_domain(domain);
                bool should_proxy_dns = (rule == RouteAction::PROXY) || (rule == RouteAction::PASS && !is_cn);
                
                LOG_DEBUG("[DNS] Query for '%s'. Rule: %d, IsCN: %d, ShouldProxy: %d", 
                          domain.c_str(), (int)rule, is_cn, should_proxy_dns);

                // If it's a foreign domain, use DNS-over-TCP (DoT)
                if (should_proxy_dns) {
                    auto on_dns_response = [listener_socket, caddr = *client_addr, domain](const char* dns_resp, int resp_len) {
                        if (resp_len > 0) {
                            DnsResponse res = parse_dns_response(dns_resp, resp_len);
                            if (res.parse_error) {
                                LOG_DEBUG("[DNS] Failed to parse DoT DNS response for '%s'.", domain.c_str());
                            } else {
                                if (res.rcode == 0 && !res.addresses.empty()) {
                                    std::string ips;
                                    for (size_t i = 0; i < res.addresses.size(); ++i) {
                                        ips += res.addresses[i];
                                        if (i < res.addresses.size() - 1) ips += ", ";
                                    }
                                    LOG_DEBUG("[DNS] Resolved '%s' to [%s] via DoT.", res.qname.c_str(), ips.c_str());
                                    
                                    uint32_t first_ip = 0;
                                    inet_pton(AF_INET, res.addresses[0].c_str(), &first_ip);
                                    DnsCache::instance().put(domain, first_ip, 1200); // Optimized: Cache for 20 minutes
                                } else if (res.rcode != 0) {
                                    LOG_DEBUG("[DNS] Failed to resolve '%s' via DoT. RCODE: %d", res.qname.c_str(), res.rcode);
                                } else {
                                    LOG_DEBUG("[DNS] Received response for '%s' via DoT (RCODE: 0, no A records).", res.qname.c_str());
                                }
                            }
                            sendto(listener_socket, dns_resp, resp_len, 0, (const sockaddr*)&caddr, sizeof(caddr));
                        } else {
                            LOG_DEBUG("[DNS] Received empty or invalid response for '%s' from DoT proxy.", domain.c_str());
                        }
                    };
                    std::vector<uint8_t> query_vec((uint8_t*)data, (uint8_t*)data + len);
                    std::make_shared<DnsOverTcpProxy>(query_vec, on_dns_response)->start();
                    return;
                }
            }
        }

        // --- 2. QUIC Blocking (Port 443) ---
        // For foreign QUIC traffic, we DROP the packets to force apps to fallback to TCP (HTTPS).
        // Domestic QUIC is allowed to go DIRECT for speed.
        if (dport == 443) {
            uint32_t ip_h = ntohl(dest->ip);
            bool is_cn = GeoChecker::instance().is_cn_ip(ip_h);
            
            if (!is_cn) {
                // Check if it's a known Tencent IP range even if geoip fails
                uint8_t first = (uint8_t)(ip_h >> 24);
                if (first == 113 || first == 183 || first == 125 || first == 157) {
                    // Tencent Bypass
                } else {
                    char src_ip[INET_ADDRSTRLEN];
                    char dst_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr->sin_addr, src_ip, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &dest->ip, dst_ip, INET_ADDRSTRLEN);
                    LOG_INFO("[UDP] Blocking foreign QUIC from %s:%d to %s:%d", 
                        src_ip, ntohs(client_addr->sin_port),
                        dst_ip, dport);
                    return; 
                }
            }
        }

        // --- 3. Flow Matching & Forwarding (Direct Relay) ---
        FlowKey flow = { client_addr->sin_addr.s_addr, client_addr->sin_port, dest->ip, dest->port };
        
        sockaddr_in target_addr = {};
        target_addr.sin_family = AF_INET;
        if (is_dns) {
            // Domestic DNS query -> Relay to 223.5.5.5
            inet_pton(AF_INET, g_config.direct_dns_server.c_str(), &target_addr.sin_addr);
            target_addr.sin_port = htons(53);
        } else {
            // General UDP or Domestic QUIC -> Relay to actual destination
            target_addr.sin_addr.s_addr = dest->ip;
            target_addr.sin_port = dest->port;
        }

        SOCKET remote_socket = get_or_create_session(flow, client_addr, &target_addr);
        if (remote_socket != INVALID_SOCKET) {
            bool success = WorkerPool::instance().send_async(remote_socket, (const uint8_t*)data, (size_t)len);
            if (!success) {
                LOG_ERROR("[UDP] send_async failed for session");
            }
            TrafficManager::instance().report_proxy_tx(len, true);
        } else {
            LOG_WARN("[UDP] Failed to create session for flow");
        }
    }

private:
    SOCKET get_or_create_session(const FlowKey& flow, const sockaddr_in* client_addr, const sockaddr_in* target_addr) {
        uint64_t now = GetTickCount64();
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_sessions.find(flow);
        if (it != m_sessions.end()) {
            const uint64_t timeout = 300000; // 300 seconds (5 minutes)
            if (now - it->second.last_access < timeout) {
                it->second.last_access = now;
                return it->second.sock;
            } else {
                // Lazy cleanup: session expired
                SOCKET s = it->second.sock;
                m_socket_to_flow.erase(s);
                WorkerPool::instance().remove_socket(s);
                closesocket(s);
                m_sessions.erase(it);
                // Continue to create a new session below
            }
        }

        // Create new socket for this flow
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        // Set SO_REUSEADDR
        BOOL reuse = TRUE;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);

        // Bind to the virtual port assigned by the driver.
        sockaddr_in local_addr = {};
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = client_addr->sin_port; // This is the virtual_port in NBO
        
        if (bind(s, (const sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
            local_addr.sin_port = 0;
            bind(s, (const sockaddr*)&local_addr, sizeof(local_addr));
        }

        // Connect the UDP socket to the target address to enable WSASend (IOCP)
        if (connect(s, (const sockaddr*)target_addr, sizeof(sockaddr_in)) == SOCKET_ERROR) {
            LOG_ERROR("[UDP] Failed to connect UDP socket: %d", WSAGetLastError());
            closesocket(s);
            return INVALID_SOCKET;
        }

        m_sessions[flow] = { s, *client_addr, now };
        m_socket_to_flow[s] = flow;

        WorkerPool::instance().add_socket(s, [this, s](char* b, int l, const sockaddr_in* f) {
            this->on_remote_data(s, b, l, f);
        }, nullptr, true);
        
        WorkerPool::instance().read_async(s);
        return s;
    }

    void on_remote_data(SOCKET s, char* buf, int len, const sockaddr_in* from) {
        if (len <= 0) {
            WorkerPool::instance().read_async(s);
            return;
        }

        // --- DNS Logging for Direct Queries ---
        sockaddr_in direct_dns_addr = {};
        inet_pton(AF_INET, g_config.direct_dns_server.c_str(), &direct_dns_addr.sin_addr);

        // Heuristic: If packet comes from direct DNS server's IP, it's a DNS response.
        if (from->sin_addr.s_addr == direct_dns_addr.sin_addr.s_addr) {
            DnsResponse res = parse_dns_response(buf, len);
            if (res.parse_error) {
                LOG_DEBUG("[DNS] Failed to parse direct DNS response.");
            }
            else {
                if (res.rcode == 0 && !res.addresses.empty()) {
                    std::string ips;
                    for (size_t i = 0; i < res.addresses.size(); ++i) {
                        ips += res.addresses[i];
                        if (i < res.addresses.size() - 1) ips += ", ";
                    }
                    LOG_DEBUG("[DNS] Resolved '%s' to [%s] via DIRECT.", res.qname.c_str(), ips.c_str());

                    // --- OPTIMIZATION: Cache Direct DNS Results ---
                    uint32_t first_ip = 0;
                    inet_pton(AF_INET, res.addresses[0].c_str(), &first_ip);
                    DnsCache::instance().put(res.qname, first_ip, 1200); // Optimized: Cache for 20 minutes
                }
                else if (res.rcode != 0) {
                    LOG_DEBUG("[DNS] Failed to resolve '%s' via DIRECT. RCODE: %d", res.qname.c_str(), res.rcode);
                }
                else {
                    LOG_DEBUG("[DNS] Received response for '%s' via DIRECT (RCODE: 0, no A records).", res.qname.c_str());
                }
            }
        }
        // --- End of DNS Logging ---

        FlowKey flow;
        sockaddr_in client_addr;
        bool found = false;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_socket_to_flow.find(s);
            if (it != m_socket_to_flow.end()) {
                flow = it->second;
                client_addr = m_sessions[flow].client_addr;
                m_sessions[flow].last_access = GetTickCount64();
                found = true;
            }
        }

        if (found) {
            SOCKET listener = (SOCKET)AppListener::instance().get_udp_socket();
            if (listener != INVALID_SOCKET) {
                bool success = WorkerPool::instance().sendto_async(listener, (const uint8_t*)buf, len, client_addr);
                if (!success) {
                    LOG_ERROR("[UDP] sendto_async back to client failed: %d", WSAGetLastError());
                } else {
                    if (len < 512 || (GetTickCount64() % 5 == 0)) {
                        LOG_DEBUG("[UDP] Forwarded %d bytes from %s:%d back to client %s:%d (IOCP)",
                            len, inet_ntoa(from->sin_addr), ntohs(from->sin_port),
                            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    }
                }
                TrafficManager::instance().report_proxy_rx(len, true);
            }
        }
        
        WorkerPool::instance().read_async(s);
    }

    void cleanup_sessions(uint64_t now) {
        const uint64_t timeout = 300000; // 300 seconds (5 minutes)
        for (auto it = m_sessions.begin(); it != m_sessions.end(); ) {
            if (now - it->second.last_access > timeout) {
                SOCKET s = it->second.sock;
                m_socket_to_flow.erase(s);
                WorkerPool::instance().remove_socket(s);
                closesocket(s);
                it = m_sessions.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Helper to parse domain name and qtype from DNS query
    std::string parse_dns_query_domain(const char* data, int len, uint16_t* out_qtype = nullptr) {
        if (len < 13) return "";
        std::string domain = "";
        const unsigned char* qname = (const unsigned char*)(data + 12);
        int pos = 0;
        while (pos < (len - 12)) {
            uint8_t label_len = qname[pos];
            if (label_len == 0) {
                pos++;
                break;
            }
            if ((label_len & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            if (pos + 1 + label_len > (len - 12)) return "";
            if (!domain.empty()) domain += ".";
            domain.append((const char*)(qname + pos + 1), label_len);
            pos += 1 + label_len;
        }
        if (out_qtype && pos + 2 <= (len - 12)) {
            *out_qtype = ntohs(*(uint16_t*)(qname + pos));
        }
        return domain;
    }

    std::mutex m_mutex;
    std::map<FlowKey, Session> m_sessions;
    std::unordered_map<SOCKET, FlowKey> m_socket_to_flow;
    uint64_t m_last_cleanup;
};

static UdpProxyManager g_udp_manager;

void UdpProxy::initialize() {
    g_udp_manager.initialize();
}

void UdpProxy::shutdown() {
    g_udp_manager.shutdown();
}

void UdpProxy::handle_client_data(SOCKET listener_socket, const char* data, int len, const sockaddr_in* client_addr, const OriginalDestination* dest) {
    g_udp_manager.handle_data(listener_socket, data, len, client_addr, dest);
}
