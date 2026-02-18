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

// A manager to handle all UDP proxy operations.
class UdpProxyManager {
public:
    UdpProxyManager() {}

    void initialize() {
    }

    void shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto const& [key, val] : m_remote_sockets) {
            if (val != INVALID_SOCKET) {
                WorkerPool::instance().remove_socket(val);
            }
        }
        m_remote_sockets.clear();
        m_reverse_routes.clear();
        LOG_INFO("[UdpProxy] Shutdown complete.");
    }

    // Helper to parse domain name from DNS query
    std::string parse_dns_query_domain(const char* data, int len) {
        if (len < 13) return ""; // Basic check for header + qname
        
        std::string domain = "";
        const unsigned char* qname = (const unsigned char*)(data + 12);
        int pos = 0;

        while (pos < (len - 12)) {
            uint8_t label_len = qname[pos];
            if (label_len == 0) {
                break;
            }
            if ((label_len & 0xC0) == 0xC0) { // Pointer
                break; 
            }
            if (pos + 1 + label_len > (len - 12)) {
                return ""; // Malformed packet
            }
            if (!domain.empty()) {
                domain += ".";
            }
            domain.append((const char*)(qname + pos + 1), label_len);
            pos += 1 + label_len;
        }
        return domain;
    }


    void handle_data(SOCKET listener_socket, const char* data, int len, const sockaddr_in* client_addr, const OriginalDestination* dest) {
        bool is_direct = true;
        uint16_t dport = ntohs(dest->port);

        // --- 1. DNS Handling (Port 53) ---
        if (dport == 53) {
            std::string domain = parse_dns_query_domain(data, len);
            if (!domain.empty()) {
                // *** DNS Cache Lookup ***
                uint32_t cached_ip = DnsCache::instance().get(domain);
                if (cached_ip != 0) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &cached_ip, ip_str, INET_ADDRSTRLEN);
                    LOG_INFO("[DNS] Cache Hit for '%s' -> %s", domain.c_str(), ip_str);
                    
                    std::vector<char> resp = build_dns_a_response(data, len, cached_ip);
                    if (!resp.empty()) {
                        sendto(listener_socket, resp.data(), (int)resp.size(), 0, (const sockaddr*)client_addr, sizeof(*client_addr));
                    }
                    return; // Intercepted
                }
                // ************************

                RouteAction rule = RuleManager::instance().match_domain(domain);
                bool is_cn = GeoChecker::instance().is_cn_domain(domain);
                bool should_proxy_dns = (rule == RouteAction::PROXY) || (rule == RouteAction::PASS && !is_cn);

                LOG_DEBUG("[DNS] Query for '%s'. Rule: %d, IsCN: %d, ShouldProxy: %d", 
                          domain.c_str(), (int)rule, is_cn, should_proxy_dns);

                if (should_proxy_dns) {
                    auto on_dns_response = [listener_socket, client_addr = *client_addr, domain](const char* dns_resp, int resp_len) {
                        if (resp_len > 0) {
                            DnsResponse res = parse_dns_response(dns_resp, resp_len);
                            if (res.parse_error) {
                                LOG_ERROR("[DNS] Failed to parse DoT DNS response for '%s'.", domain.c_str());
                            } else {
                                if (res.rcode == 0 && !res.addresses.empty()) {
                                    std::string ips;
                                    uint32_t first_ip_nbo = 0;
                                    for (size_t i = 0; i < res.addresses.size(); ++i) {
                                        ips += res.addresses[i];
                                        if (i < res.addresses.size() - 1) ips += ", ";
                                        if (i == 0) inet_pton(AF_INET, res.addresses[i].c_str(), &first_ip_nbo);
                                    }
                                    LOG_INFO("[DNS] Resolved '%s' to [%s] via DoT.", res.qname.c_str(), ips.c_str());
                                    
                                    // *** Write to Cache ***
                                    if (first_ip_nbo != 0) {
                                        DnsCache::instance().put(domain, first_ip_nbo, 300); // TTL 300s
                                    }
                                    // **********************

                                } else if (res.rcode != 0) {
                                    LOG_INFO("[DNS] Failed to resolve '%s' via DoT. RCODE: %d", res.qname.c_str(), res.rcode);
                                } else {
                                    LOG_INFO("[DNS] Received response for '%s' via DoT (RCODE: 0, no A records).", res.qname.c_str());
                                }
                            }
                            sendto(listener_socket, dns_resp, resp_len, 0, (const sockaddr*)&client_addr, sizeof(client_addr));
                        } else {
                            LOG_ERROR("[DNS] Received empty or invalid response for '%s' from DoT proxy.", domain.c_str());
                        }
                    };
                    std::vector<uint8_t> query_vec((uint8_t*)data, (uint8_t*)data + len);
                    std::make_shared<DnsOverTcpProxy>(query_vec, on_dns_response)->start();
                    return;
                }
            }
            is_direct = true;
        } 
        // --- 2. QUIC Handling (Port 443) ---
        else if (dport == 443) {
            uint32_t ip_h = ntohl(dest->ip);
            RouteAction rule = RuleManager::instance().match_ip(ip_h);
            
            bool is_cn = (rule == RouteAction::DIRECT) || (rule == RouteAction::PASS && GeoChecker::instance().is_cn_ip(ip_h));
            
            if (!is_cn) {
                unsigned char* ip_bytes = (unsigned char*)&(dest->ip);
                char ip_str[INET_ADDRSTRLEN];
                snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                LOG_DEBUG("[UdpProxy] Dropping international QUIC packet to %s", ip_str);
                return; // DROP
            }
            is_direct = true;
        }
        // --- 3. General UDP Handling ---
        else {
            is_direct = true; // Always direct for general UDP
        }
        
        // --- 4. Forwarding (Direct Relay) ---
        sockaddr_in dest_addr_sock = {};
        dest_addr_sock.sin_family = AF_INET;

        if (is_direct && dport == 53) {
            LOG_DEBUG("[DNS] Relaying DNS query for direct route to: %s", g_config.direct_dns_server.c_str());
            inet_pton(AF_INET, g_config.direct_dns_server.c_str(), &dest_addr_sock.sin_addr);
            dest_addr_sock.sin_port = htons(53);
        }
        else {
            dest_addr_sock.sin_addr.s_addr = dest->ip;
            dest_addr_sock.sin_port = dest->port;
        }

        uint64_t dest_key = ((uint64_t)dest->ip << 16) | dport;
        SOCKET remote_socket = get_or_create_remote_socket(dest_key, client_addr);

        if (remote_socket != INVALID_SOCKET) {
            int bytes_sent = sendto(remote_socket, data, len, 0, (const sockaddr*)&dest_addr_sock, sizeof(dest_addr_sock));
            if (bytes_sent != SOCKET_ERROR) {
                 TrafficManager::instance().report_proxy_tx(bytes_sent, is_direct);
            }
        }
    }

private:
    void on_remote_read(SOCKET remote_socket, char* buf, int len, const sockaddr_in* from_addr) {
        if (len <= 0) {
            // Re-post a read even on error to keep the loop alive for UDP
            WorkerPool::instance().read_async(remote_socket);
            return;
        }

        TrafficManager::instance().report_proxy_rx(len, true); // Assuming direct

        // --- DNS Logging for Direct Queries ---
        sockaddr_in direct_dns_addr = {};
        inet_pton(AF_INET, g_config.direct_dns_server.c_str(), &direct_dns_addr.sin_addr);

        // Heuristic: If packet comes from direct DNS server's IP, it's a DNS response.
        if (from_addr->sin_addr.s_addr == direct_dns_addr.sin_addr.s_addr) {
            DnsResponse res = parse_dns_response(buf, len);
            if (res.parse_error) {
                LOG_ERROR("[DNS] Failed to parse direct DNS response.");
            }
            else {
                if (res.rcode == 0 && !res.addresses.empty()) {
                    std::string ips;
                    uint32_t first_ip_nbo = 0;
                    for (size_t i = 0; i < res.addresses.size(); ++i) {
                        ips += res.addresses[i];
                        if (i < res.addresses.size() - 1) ips += ", ";
                        if (i == 0) inet_pton(AF_INET, res.addresses[i].c_str(), &first_ip_nbo);
                    }
                    LOG_INFO("[DNS] Resolved '%s' to [%s] via DIRECT.", res.qname.c_str(), ips.c_str());

                    // *** Write to Cache ***
                    if (first_ip_nbo != 0) {
                        DnsCache::instance().put(res.qname, first_ip_nbo, 300);
                    }
                    // **********************

                }
                else if (res.rcode != 0) {
                    LOG_INFO("[DNS] Failed to resolve '%s' via DIRECT. RCODE: %d", res.qname.c_str(), res.rcode);
                }
                else {
                    LOG_INFO("[DNS] Received response for '%s' via DIRECT (RCODE: 0, no A records).", res.qname.c_str());
                }
            }
        }
        // --- End of DNS Logging ---

        sockaddr_in client_addr_to_send;
        bool found = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_reverse_routes.find(remote_socket);
            if (it != m_reverse_routes.end()) {
                client_addr_to_send = it->second;
                found = true;
            }
        }

        if (found) {
            SOCKET listener_socket = (SOCKET)AppListener::instance().get_udp_socket();
            if (listener_socket != INVALID_SOCKET) {
                sendto(listener_socket, buf, len, 0, (const sockaddr*)&client_addr_to_send, sizeof(client_addr_to_send));
            }
        }
        else {
            LOG_ERROR("[UdpProxy] Received a UDP packet on a remote socket but could not find a reverse route.");
        }
        
        // Post another read to continue receiving packets on this remote socket
        WorkerPool::instance().read_async(remote_socket);
    }
    
    SOCKET get_or_create_remote_socket(uint64_t dest_key, const sockaddr_in* client_addr) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_remote_sockets.find(dest_key);
        if (it != m_remote_sockets.end()) {
            m_reverse_routes[it->second] = *client_addr;
            return it->second;
        }

        SOCKET new_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (new_socket == INVALID_SOCKET) {
            LOG_ERROR("[UdpProxy] Failed to create remote UDP socket.");
            return INVALID_SOCKET;
        }
        
        u_long mode = 1;
        ioctlsocket(new_socket, FIONBIO, &mode);
        
        WorkerPool::instance().add_socket(
            new_socket,
            [this, new_socket](char* buf, int len, const sockaddr_in* from) { this->on_remote_read(new_socket, buf, len, from); },
            nullptr,
            true
        );

        m_remote_sockets[dest_key] = new_socket;
        m_reverse_routes[new_socket] = *client_addr;
        
        WorkerPool::instance().read_async(new_socket);

        LOG_DEBUG("[UdpProxy] Created new remote UDP socket for dest key %llu", dest_key);

        return new_socket;
    }

    std::mutex m_mutex;
    std::unordered_map<uint64_t, SOCKET> m_remote_sockets;
    std::unordered_map<SOCKET, sockaddr_in> m_reverse_routes;
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
