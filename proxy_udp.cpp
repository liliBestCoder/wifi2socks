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
#include "dns_probe_tracker.h"
#include "winpkfilter_driver.h"

#include <unordered_map>
#include <mutex>
#include <memory>
#include <vector>
#include <string>
#include <ws2tcpip.h>
#include <atomic>
#include <algorithm>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

static uint32_t clamp_dns_cache_ttl(uint32_t ttl) {
    if (ttl == 0) return 300;
    if (ttl < 60) return 60;
    if (ttl > 600) return 600;
    return ttl;
}

struct UdpDnsCounters {
    std::atomic<uint64_t> dns_queries{0};
    std::atomic<uint64_t> dns_cache_hits{0};
    std::atomic<uint64_t> dns_aaaa_blocked{0};
    std::atomic<uint64_t> dns_dot_queries{0};
    std::atomic<uint64_t> dns_dot_responses{0};
    std::atomic<uint64_t> dns_dot_failures{0};
    std::atomic<uint64_t> dns_dot_nxdomain{0};
    std::atomic<uint64_t> dns_dot_rcode_failures{0};
    std::atomic<uint64_t> dns_direct_queries{0};
    std::atomic<uint64_t> dns_direct_responses{0};
    std::atomic<uint64_t> dns_direct_failures{0};
};

static UdpDnsCounters g_udp_dns_counters;
static std::atomic<uint64_t> g_udp_pressure_drops{ 0 };

static const char* dns_qtype_name(uint16_t qtype) {
    switch (qtype) {
    case 1: return "A";
    case 28: return "AAAA";
    case 65: return "HTTPS";
    default: return "OTHER";
    }
}

static std::string lower_ascii_udp(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    if (!s.empty() && s.back() == '.') s.pop_back();
    return s;
}

static bool domain_is_or_under_udp(const std::string& host, const char* domain) {
    std::string h = lower_ascii_udp(host);
    std::string d(domain);
    if (h == d) return true;
    return h.size() > d.size() &&
        h.compare(h.size() - d.size(), d.size(), d) == 0 &&
        h[h.size() - d.size() - 1] == '.';
}

static bool is_netcheck_dns_domain(const std::string& domain) {
    return domain_is_or_under_udp(domain, "connectivitycheck.gstatic.com") ||
        domain_is_or_under_udp(domain, "connectivitycheck.android.com") ||
        domain_is_or_under_udp(domain, "clients3.google.com") ||
        domain_is_or_under_udp(domain, "clients4.google.com") ||
        domain_is_or_under_udp(domain, "www.google.com") ||
        domain_is_or_under_udp(domain, "www.google.cn") ||
        domain_is_or_under_udp(domain, "google.com") ||
        domain_is_or_under_udp(domain, "google.cn") ||
        domain_is_or_under_udp(domain, "gstatic.com") ||
        domain_is_or_under_udp(domain, "googleapis.com") ||
        domain_is_or_under_udp(domain, "gvt1.com") ||
        domain_is_or_under_udp(domain, "gvt2.com") ||
        domain_is_or_under_udp(domain, "android.com") ||
        domain_is_or_under_udp(domain, "captive.apple.com") ||
        domain_is_or_under_udp(domain, "apple.com") ||
        domain_is_or_under_udp(domain, "msftconnecttest.com") ||
        domain_is_or_under_udp(domain, "msftncsi.com") ||
        domain_is_or_under_udp(domain, "connectivitycheck.platform.hicloud.com") ||
        domain_is_or_under_udp(domain, "connect.rom.miui.com") ||
        domain_is_or_under_udp(domain, "allawntech.com") ||
        domain_is_or_under_udp(domain, "heytapmobi.com") ||
        domain_is_or_under_udp(domain, "heytapmobile.com") ||
        domain_is_or_under_udp(domain, "coloros.com") ||
        domain_is_or_under_udp(domain, "oppomobile.com") ||
        domain_is_or_under_udp(domain, "oppo.com");
}

static bool strip_mshome_suffix(std::string domain, std::string& stripped) {
    domain = lower_ascii_udp(domain);
    constexpr const char* suffix = ".mshome.net";
    constexpr size_t suffix_len = 11;
    if (domain.size() <= suffix_len) return false;
    if (domain.compare(domain.size() - suffix_len, suffix_len, suffix) != 0) return false;
    stripped = domain.substr(0, domain.size() - suffix_len);
    return stripped.find('.') != std::string::npos;
}

static bool encode_dns_qname(const std::string& domain, std::vector<uint8_t>& out) {
    size_t start = 0;
    while (start < domain.size()) {
        size_t dot = domain.find('.', start);
        size_t end = (dot == std::string::npos) ? domain.size() : dot;
        size_t label_len = end - start;
        if (label_len == 0 || label_len > 63) return false;
        out.push_back((uint8_t)label_len);
        out.insert(out.end(), domain.begin() + start, domain.begin() + end);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    out.push_back(0);
    return true;
}

static bool rewrite_dns_query_domain(const char* data, int len, const std::string& domain, std::vector<uint8_t>& out) {
    if (len < 17) return false;
    const unsigned char* qname = (const unsigned char*)(data + 12);
    int pos = 0;
    while (pos < (len - 12)) {
        uint8_t label_len = qname[pos];
        if (label_len == 0) {
            ++pos;
            break;
        }
        if ((label_len & 0xC0) == 0xC0) return false;
        if (pos + 1 + label_len > (len - 12)) return false;
        pos += 1 + label_len;
    }
    if (pos + 4 > (len - 12)) return false;

    out.clear();
    out.reserve((size_t)len);
    out.insert(out.end(), (const uint8_t*)data, (const uint8_t*)data + 12);
    if (!encode_dns_qname(domain, out)) return false;
    out.insert(out.end(), (const uint8_t*)(data + 12 + pos), (const uint8_t*)data + len);
    return true;
}

// Struct to hold DNS response details
struct DnsResponse {
    std::string qname;
    uint16_t qtype;
    uint16_t rcode;
    std::vector<std::string> addresses;
    uint32_t min_ttl = 0;
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
        uint32_t ttl = ntohl(*(uint32_t*)(p + 4));
        uint16_t data_len = ntohs(*(uint16_t*)(p + 8));
        p += 10;

        if (type == 1 && data_len == 4) { // TYPE A record
            if (p + 4 <= data + len) {
                char ip_str[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, p, ip_str, INET_ADDRSTRLEN)) {
                    res.addresses.push_back(ip_str);
                    if (res.min_ttl == 0 || ttl < res.min_ttl) {
                        res.min_ttl = ttl;
                    }
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

        bool operator==(const FlowKey& o) const {
            return src_ip == o.src_ip &&
                src_port == o.src_port &&
                dst_ip == o.dst_ip &&
                dst_port == o.dst_port;
        }
    };

    struct FlowKeyHash {
        size_t operator()(const FlowKey& key) const {
            uint64_t h = ((uint64_t)key.src_ip << 32) ^ key.dst_ip;
            h ^= ((uint64_t)key.src_port << 48) ^ ((uint64_t)key.dst_port << 16);
            h ^= h >> 33;
            h *= 0xff51afd7ed558ccdULL;
            h ^= h >> 33;
            return (size_t)h;
        }
    };

    struct Session {
        SOCKET sock;
        sockaddr_in client_addr;
        uint64_t last_access;
        uint64_t first_tx_time;
        uint64_t tx_bytes;
        uint64_t rx_bytes;
        uint32_t tx_packets;
        uint32_t rx_packets;
        bool first_response_logged;
    };

    using SessionMap = std::unordered_map<FlowKey, Session, FlowKeyHash>;

    void handle_data(SOCKET listener_socket, const char* data, int len, const sockaddr_in* client_addr, const OriginalDestination* dest) {
        uint64_t now = GetTickCount64();
        if (now - m_last_cleanup > CLEANUP_INTERVAL_MS) {
            std::lock_guard<std::mutex> lock(m_mutex);
            cleanup_sessions(now);
            m_last_cleanup = now;
        }

        uint16_t dport = ntohs(dest->port);
        bool is_dns = (dport == 53);

        // --- 1. DNS Interception ---
        if (is_dns) {
            g_udp_dns_counters.dns_queries.fetch_add(1, std::memory_order_relaxed);
            uint16_t qtype = 0;
            std::string domain = parse_dns_query_domain(data, len, &qtype);
            if (!domain.empty()) {
                std::string lookup_domain = domain;
                std::vector<uint8_t> rewritten_query;
                bool mshome_rewrite = false;
                std::string stripped_domain;
                if (qtype == 1 && strip_mshome_suffix(domain, stripped_domain) &&
                    rewrite_dns_query_domain(data, len, stripped_domain, rewritten_query)) {
                    lookup_domain = stripped_domain;
                    mshome_rewrite = true;
                    LOG_WARN("[NETCHECKDNS] stage=mshome_rewrite domain=%s lookup=%s qtype=%u/%s",
                        domain.c_str(), lookup_domain.c_str(), qtype, dns_qtype_name(qtype));
                }

                bool is_netcheck_dns = is_netcheck_dns_domain(domain) || is_netcheck_dns_domain(lookup_domain);
                if (qtype == 28) { // AAAA Record (IPv6)
                    g_udp_dns_counters.dns_aaaa_blocked.fetch_add(1, std::memory_order_relaxed);
                    LOG_DEBUG("[DNS] Blocking AAAA query for '%s' to force IPv4 fallback", domain.c_str());
                    if (is_netcheck_dns) {
                        LOG_WARN("[NETCHECKDNS] stage=aaaa_block domain=%s qtype=%u/%s",
                            domain.c_str(), qtype, dns_qtype_name(qtype));
                    }
                    std::vector<char> resp = build_dns_empty_response(data, len);
                    if (!resp.empty()) {
                        sendto(listener_socket, resp.data(), (int)resp.size(), 0, (const sockaddr*)client_addr, sizeof(*client_addr));
                    }
                    return;
                }

                uint32_t cached_ip = (qtype == 1) ? DnsCache::instance().get(lookup_domain) : 0;
                if (cached_ip != 0) {
                    g_udp_dns_counters.dns_cache_hits.fetch_add(1, std::memory_order_relaxed);
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &cached_ip, ip_str, INET_ADDRSTRLEN);
                    DnsProbeTracker::instance().put(cached_ip, lookup_domain, 300);
                    LOG_DEBUG("[DNS] Cache Hit for '%s' -> %s", lookup_domain.c_str(), ip_str);
                    if (is_netcheck_dns) {
                        LOG_WARN("[NETCHECKDNS] stage=cache_hit domain=%s qtype=%u/%s ip=%s",
                            lookup_domain.c_str(), qtype, dns_qtype_name(qtype), ip_str);
                    }

                    std::vector<char> resp = build_dns_a_response(data, len, cached_ip);
                    if (!resp.empty()) {
                        sendto(listener_socket, resp.data(), (int)resp.size(), 0, (const sockaddr*)client_addr, sizeof(*client_addr));
                    }
                    return;
                }

                RouteAction rule = RuleManager::instance().match_domain(lookup_domain);
                bool is_cn = GeoChecker::instance().is_cn_domain(lookup_domain);
                bool should_proxy_dns = (rule == RouteAction::PROXY) || (rule == RouteAction::PASS && !is_cn);
                
                LOG_DEBUG("[DNS] Query for '%s'. Rule: %d, IsCN: %d, ShouldProxy: %d", 
                          lookup_domain.c_str(), (int)rule, is_cn, should_proxy_dns);
                if (is_netcheck_dns) {
                    LOG_WARN("[NETCHECKDNS] stage=query domain=%s qtype=%u/%s rule=%d is_cn=%d via=%s",
                        lookup_domain.c_str(), qtype, dns_qtype_name(qtype), (int)rule, is_cn ? 1 : 0,
                        should_proxy_dns ? "DoT" : "DIRECT");
                }

                // If it's a foreign domain, use DNS-over-TCP (DoT)
                if (should_proxy_dns) {
                    g_udp_dns_counters.dns_dot_queries.fetch_add(1, std::memory_order_relaxed);
                    std::vector<uint8_t> original_query((uint8_t*)data, (uint8_t*)data + len);
                    auto on_dns_response = [listener_socket, caddr = *client_addr, domain = lookup_domain, qtype, is_netcheck_dns, mshome_rewrite, original_query](const char* dns_resp, int resp_len) {
                        if (resp_len > 0) {
                            g_udp_dns_counters.dns_dot_responses.fetch_add(1, std::memory_order_relaxed);
                            DnsResponse res = parse_dns_response(dns_resp, resp_len);
                            if (res.parse_error) {
                                g_udp_dns_counters.dns_dot_failures.fetch_add(1, std::memory_order_relaxed);
                                LOG_WARN("[DNSFAIL] via=DoT reason=parse_error domain=%s qtype=%u/%s resp_len=%d",
                                         domain.c_str(), qtype, dns_qtype_name(qtype), resp_len);
                            } else {
                                if (res.rcode == 0 && !res.addresses.empty()) {
                                    std::string ips;
                                    for (size_t i = 0; i < res.addresses.size(); ++i) {
                                        ips += res.addresses[i];
                                        if (i < res.addresses.size() - 1) ips += ", ";
                                    }
                                    LOG_DEBUG("[DNS] Resolved '%s' to [%s] via DoT.", res.qname.c_str(), ips.c_str());
                                    if (is_netcheck_dns) {
                                        LOG_WARN("[NETCHECKDNS] stage=response via=DoT domain=%s qname=%s qtype=%u/%s rcode=%u ttl=%u ips=%s",
                                            domain.c_str(), res.qname.c_str(), qtype, dns_qtype_name(qtype), res.rcode, res.min_ttl, ips.c_str());
                                    }
                                    
                                    uint32_t first_ip = 0;
                                    inet_pton(AF_INET, res.addresses[0].c_str(), &first_ip);
                                    uint32_t cache_ttl = clamp_dns_cache_ttl(res.min_ttl);
                                    if (qtype == 1) {
                                        DnsProbeTracker::instance().put_many(res.addresses, domain, cache_ttl);
                                        DnsCache::instance().put(domain, first_ip, cache_ttl);
                                        LOG_DEBUG("[DNS] Cached '%s' for %u seconds via DoT.", domain.c_str(), cache_ttl);
                                    }
                                    if (mshome_rewrite && qtype == 1) {
                                        std::vector<char> resp = build_dns_a_response((const char*)original_query.data(), (int)original_query.size(), first_ip);
                                        if (!resp.empty()) {
                                            sendto(listener_socket, resp.data(), (int)resp.size(), 0, (const sockaddr*)&caddr, sizeof(caddr));
                                            return;
                                        }
                                    }
                                } else if (res.rcode != 0) {
                                    if (res.rcode == 3) {
                                        g_udp_dns_counters.dns_dot_nxdomain.fetch_add(1, std::memory_order_relaxed);
                                        LOG_DEBUG("[DNSMISS] via=DoT reason=nxdomain domain=%s qname=%s qtype=%u/%s resp_qtype=%u resp_len=%d",
                                                  domain.c_str(), res.qname.c_str(), qtype, dns_qtype_name(qtype), res.qtype, resp_len);
                                        if (is_netcheck_dns) {
                                            LOG_WARN("[NETCHECKDNS] stage=response via=DoT domain=%s qname=%s qtype=%u/%s rcode=%u reason=nxdomain",
                                                domain.c_str(), res.qname.c_str(), qtype, dns_qtype_name(qtype), res.rcode);
                                        }
                                    } else {
                                        g_udp_dns_counters.dns_dot_rcode_failures.fetch_add(1, std::memory_order_relaxed);
                                        LOG_WARN("[DNSFAIL] via=DoT reason=rcode domain=%s qname=%s qtype=%u/%s resp_qtype=%u rcode=%u resp_len=%d",
                                                 domain.c_str(), res.qname.c_str(), qtype, dns_qtype_name(qtype), res.qtype, res.rcode, resp_len);
                                        if (is_netcheck_dns) {
                                            LOG_WARN("[NETCHECKDNS] stage=response via=DoT domain=%s qname=%s qtype=%u/%s rcode=%u reason=rcode",
                                                domain.c_str(), res.qname.c_str(), qtype, dns_qtype_name(qtype), res.rcode);
                                        }
                                    }
                                } else {
                                    LOG_DEBUG("[DNS] Received response for '%s' via DoT (RCODE: 0, no A records).", res.qname.c_str());
                                    if (is_netcheck_dns) {
                                        LOG_WARN("[NETCHECKDNS] stage=response via=DoT domain=%s qname=%s qtype=%u/%s rcode=%u reason=no_a",
                                            domain.c_str(), res.qname.c_str(), qtype, dns_qtype_name(qtype), res.rcode);
                                    }
                                }
                            }
                            sendto(listener_socket, dns_resp, resp_len, 0, (const sockaddr*)&caddr, sizeof(caddr));
                        } else {
                            g_udp_dns_counters.dns_dot_failures.fetch_add(1, std::memory_order_relaxed);
                            LOG_WARN("[DNSFAIL] via=DoT reason=empty_response domain=%s qtype=%u/%s resp_len=%d",
                                     domain.c_str(), qtype, dns_qtype_name(qtype), resp_len);
                            if (is_netcheck_dns) {
                                LOG_WARN("[NETCHECKDNS] stage=response via=DoT domain=%s qtype=%u/%s reason=empty_response",
                                    domain.c_str(), qtype, dns_qtype_name(qtype));
                            }
                        }
                    };
                    std::vector<uint8_t> query_vec = mshome_rewrite ? rewritten_query : std::vector<uint8_t>((uint8_t*)data, (uint8_t*)data + len);
                    std::make_shared<DnsOverTcpProxy>(query_vec, on_dns_response)->start();
                    return;
                }

                g_udp_dns_counters.dns_direct_queries.fetch_add(1, std::memory_order_relaxed);
                std::vector<uint8_t> original_query((uint8_t*)data, (uint8_t*)data + len);
                auto on_dns_response = [listener_socket, caddr = *client_addr, domain = lookup_domain, qtype, is_netcheck_dns, mshome_rewrite, original_query](const char* dns_resp, int resp_len) {
                    if (resp_len > 0) {
                        g_udp_dns_counters.dns_direct_responses.fetch_add(1, std::memory_order_relaxed);
                        DnsResponse res = parse_dns_response(dns_resp, resp_len);
                        if (res.parse_error) {
                            g_udp_dns_counters.dns_direct_failures.fetch_add(1, std::memory_order_relaxed);
                            LOG_DEBUG("[DNS] Failed to parse direct TCP DNS response for '%s'.", domain.c_str());
                        } else {
                            if (res.rcode == 0 && !res.addresses.empty()) {
                                if (is_netcheck_dns) {
                                    std::string ips;
                                    for (size_t i = 0; i < res.addresses.size(); ++i) {
                                        ips += res.addresses[i];
                                        if (i < res.addresses.size() - 1) ips += ", ";
                                    }
                                    LOG_WARN("[NETCHECKDNS] stage=response via=DIRECT domain=%s qname=%s qtype=%u/%s rcode=%u ttl=%u ips=%s",
                                        domain.c_str(), res.qname.c_str(), qtype, dns_qtype_name(qtype), res.rcode, res.min_ttl, ips.c_str());
                                }
                                uint32_t first_ip = 0;
                                inet_pton(AF_INET, res.addresses[0].c_str(), &first_ip);
                                uint32_t cache_ttl = clamp_dns_cache_ttl(res.min_ttl);
                                if (qtype == 1) {
                                    DnsProbeTracker::instance().put_many(res.addresses, domain, cache_ttl);
                                    DnsCache::instance().put(domain, first_ip, cache_ttl);
                                    LOG_DEBUG("[DNS] Cached '%s' for %u seconds via DIRECT-TCP.", domain.c_str(), cache_ttl);
                                }
                                if (mshome_rewrite && qtype == 1) {
                                    std::vector<char> resp = build_dns_a_response((const char*)original_query.data(), (int)original_query.size(), first_ip);
                                    if (!resp.empty()) {
                                        sendto(listener_socket, resp.data(), (int)resp.size(), 0, (const sockaddr*)&caddr, sizeof(caddr));
                                        return;
                                    }
                                }
                            } else if (res.rcode != 0) {
                                g_udp_dns_counters.dns_direct_failures.fetch_add(1, std::memory_order_relaxed);
                                LOG_DEBUG("[DNS] Failed to resolve '%s' via DIRECT-TCP. RCODE: %d", res.qname.c_str(), res.rcode);
                                if (is_netcheck_dns) {
                                    LOG_WARN("[NETCHECKDNS] stage=response via=DIRECT domain=%s qname=%s qtype=%u/%s rcode=%u reason=rcode",
                                        domain.c_str(), res.qname.c_str(), qtype, dns_qtype_name(qtype), res.rcode);
                                }
                            } else if (is_netcheck_dns) {
                                LOG_WARN("[NETCHECKDNS] stage=response via=DIRECT domain=%s qname=%s qtype=%u/%s rcode=%u reason=no_a",
                                    domain.c_str(), res.qname.c_str(), qtype, dns_qtype_name(qtype), res.rcode);
                            }
                        }
                        sendto(listener_socket, dns_resp, resp_len, 0, (const sockaddr*)&caddr, sizeof(caddr));
                    } else {
                        g_udp_dns_counters.dns_direct_failures.fetch_add(1, std::memory_order_relaxed);
                        LOG_DEBUG("[DNS] Received empty or invalid response for '%s' from direct TCP DNS.", domain.c_str());
                        if (is_netcheck_dns) {
                            LOG_WARN("[NETCHECKDNS] stage=response via=DIRECT domain=%s qtype=%u/%s reason=empty_response",
                                domain.c_str(), qtype, dns_qtype_name(qtype));
                        }
                    }
                };
                std::vector<uint8_t> query_vec = mshome_rewrite ? rewritten_query : std::vector<uint8_t>((uint8_t*)data, (uint8_t*)data + len);
                std::make_shared<DnsOverTcpProxy>(query_vec, on_dns_response, g_config.direct_dns_server, true)->start();
                return;
            }
        }

        if (ProxyTCP::pressure_high()) {
            uint64_t drops = g_udp_pressure_drops.fetch_add(1, std::memory_order_relaxed) + 1;
            if (drops <= 20 || (drops % 100) == 0) {
                char src_ip[INET_ADDRSTRLEN] = "unknown";
                char dst_ip[INET_ADDRSTRLEN] = "unknown";
                inet_ntop(AF_INET, &client_addr->sin_addr, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET, &dest->ip, dst_ip, sizeof(dst_ip));
                LOG_WARN("[PRESSURE] action=drop_udp client=%s:%u target=%s:%u level=%d drops=%llu",
                    src_ip,
                    ntohs(client_addr->sin_port),
                    dst_ip,
                    dport,
                    ProxyTCP::pressure_level(),
                    (unsigned long long)drops);
            }
            if (dport == 443) {
                WinPkFilterDriver::instance().send_icmp_port_unreachable(
                    client_addr->sin_addr.s_addr,
                    client_addr->sin_port,
                    dest->ip,
                    dest->port
                );
            }
            return;
        }

        // --- 2. QUIC Blocking (Port 443) ---
        // For foreign QUIC traffic, we DROP the packets to force apps to fallback to TCP (HTTPS).
        // Domestic QUIC is allowed to go DIRECT for speed.
        if (dport == 443) {
            uint32_t ip_h = ntohl(dest->ip);
            bool is_cn = GeoChecker::instance().is_cn_ip(ip_h);

            if (!is_cn) {
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr->sin_addr, src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &dest->ip, dst_ip, INET_ADDRSTRLEN);
                LOG_INFO("[UDP] Blocking foreign QUIC from %s:%d to %s:%d",
                    src_ip, ntohs(client_addr->sin_port), dst_ip, dport);

                // Tell the client quickly so Chromium/Android falls back to TCP instead of retrying QUIC.
                WinPkFilterDriver::instance().send_icmp_port_unreachable(
                    client_addr->sin_addr.s_addr,
                    client_addr->sin_port,
                    dest->ip,
                    dest->port
                );
                return;
            }
        }

        // --- 3. Flow Matching & Forwarding (Direct Relay) ---
        FlowKey flow = { client_addr->sin_addr.s_addr, client_addr->sin_port, dest->ip, dest->port };
        if (!is_dns) {
            LOG_DEBUG("[UDP-Out] Received packet for flow %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u",
                flow.src_ip & 0xFF, (flow.src_ip >> 8) & 0xFF, (flow.src_ip >> 16) & 0xFF, (flow.src_ip >> 24) & 0xFF, ntohs(flow.src_port),
                flow.dst_ip & 0xFF, (flow.dst_ip >> 8) & 0xFF, (flow.dst_ip >> 16) & 0xFF, (flow.dst_ip >> 24) & 0xFF, ntohs(flow.dst_port));
        }
        
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

        char target_ip[INET_ADDRSTRLEN] = "unknown";
        inet_ntop(AF_INET, &target_addr.sin_addr, target_ip, sizeof(target_ip));
        if (ntohs(target_addr.sin_port) == g_config.upstream_port ||
            ntohs(flow.dst_port) == g_config.upstream_port ||
            target_addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK) ||
            flow.dst_ip == htonl(INADDR_LOOPBACK)) {
            LOG_DEBUG("[UDPTRACE] before_session client=%u.%u.%u.%u:%u flow_dst=%u.%u.%u.%u:%u flow_raw=%08X:%04X dest_raw=%08X:%04X target=%s:%u target_raw=%08X:%04X len=%d",
                flow.src_ip & 0xFF, (flow.src_ip >> 8) & 0xFF, (flow.src_ip >> 16) & 0xFF, (flow.src_ip >> 24) & 0xFF, ntohs(flow.src_port),
                flow.dst_ip & 0xFF, (flow.dst_ip >> 8) & 0xFF, (flow.dst_ip >> 16) & 0xFF, (flow.dst_ip >> 24) & 0xFF, ntohs(flow.dst_port),
                ntohl(flow.dst_ip), ntohs(flow.dst_port),
                ntohl(dest->ip), ntohs(dest->port),
                target_ip, ntohs(target_addr.sin_port),
                ntohl(target_addr.sin_addr.s_addr), ntohs(target_addr.sin_port),
                len);
        }

        SOCKET remote_socket = get_or_create_session(flow, client_addr, &target_addr);
        if (remote_socket != INVALID_SOCKET) {
            bool success = WorkerPool::instance().sendto_async(remote_socket, (const uint8_t*)data, (size_t)len, target_addr);
            if (!success) {
                LOG_ERROR("[UDP] sendto_async failed for session");
            }
            else {
                std::lock_guard<std::mutex> lock(m_mutex);
                auto it = m_sessions.find(flow);
                if (it != m_sessions.end()) {
                    it->second.last_access = now;
                    it->second.tx_packets++;
                    it->second.tx_bytes += (uint64_t)len;
                }
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
            const uint64_t timeout = timeout_for_session(flow, it->second, now);
            if (timeout == 0 || now - it->second.last_access < timeout) {
                it->second.last_access = now;
                return it->second.sock;
            } else {
                // Lazy cleanup: session expired
                remove_session_locked(it);
                // Continue to create a new session below
            }
        }

        if (m_sessions.size() >= MAX_SESSIONS) {
            cleanup_sessions(now, true);
        }

        // Create new socket for this flow
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        BOOL new_behavior = FALSE;
        DWORD bytes_returned = 0;
        WSAIoctl(s, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior), nullptr, 0, &bytes_returned, nullptr, nullptr);

        // Set SO_REUSEADDR
        BOOL reuse = TRUE;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);

        // Use an OS-assigned local port for the upstream UDP socket. The WFD virtual port
        // is only needed when sending the response back through the listener socket.
        sockaddr_in local_addr = {};
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = 0;
        
        if (bind(s, (const sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
            int err = WSAGetLastError();
            LOG_ERROR("[UDP] Failed to bind upstream UDP socket: %d", err);
            closesocket(s);
            return INVALID_SOCKET;
        }

        m_sessions[flow] = { s, *client_addr, now, now, 0, 0, 0, 0, false };
        m_socket_to_flow[s] = flow;

        sockaddr_in actual_local = {};
        int actual_len = sizeof(actual_local);
        char target_ip[INET_ADDRSTRLEN] = "unknown";
        char local_ip[INET_ADDRSTRLEN] = "unknown";
        inet_ntop(AF_INET, &target_addr->sin_addr, target_ip, sizeof(target_ip));
        if (getsockname(s, (sockaddr*)&actual_local, &actual_len) == 0) {
            inet_ntop(AF_INET, &actual_local.sin_addr, local_ip, sizeof(local_ip));
        }
        sockaddr_in actual_peer = {};
        int peer_len = sizeof(actual_peer);
        char peer_ip[INET_ADDRSTRLEN] = "unknown";
        int peer_port = 0;
        if (getpeername(s, (sockaddr*)&actual_peer, &peer_len) == 0) {
            inet_ntop(AF_INET, &actual_peer.sin_addr, peer_ip, sizeof(peer_ip));
            peer_port = ntohs(actual_peer.sin_port);
        } else {
            strcpy_s(peer_ip, sizeof(peer_ip), "unconnected");
        }
        LOG_DEBUG("[UDPSESSION] sock=%llu client=%u.%u.%u.%u:%u flow_dst=%u.%u.%u.%u:%u flow_raw=%08X:%04X target=%s:%u target_raw=%08X:%04X local=%s:%u peer=%s:%u peer_raw=%08X:%04X vport=%u",
            (unsigned long long)s,
            flow.src_ip & 0xFF, (flow.src_ip >> 8) & 0xFF, (flow.src_ip >> 16) & 0xFF, (flow.src_ip >> 24) & 0xFF, ntohs(flow.src_port),
            flow.dst_ip & 0xFF, (flow.dst_ip >> 8) & 0xFF, (flow.dst_ip >> 16) & 0xFF, (flow.dst_ip >> 24) & 0xFF, ntohs(flow.dst_port),
            ntohl(flow.dst_ip), ntohs(flow.dst_port),
            target_ip,
            ntohs(target_addr->sin_port),
            ntohl(target_addr->sin_addr.s_addr), ntohs(target_addr->sin_port),
            local_ip,
            ntohs(actual_local.sin_port),
            peer_ip,
            peer_port,
            ntohl(actual_peer.sin_addr.s_addr), peer_port,
            ntohs(client_addr->sin_port));
        if (ntohs(target_addr->sin_port) == g_config.upstream_port ||
            ntohs(flow.dst_port) == g_config.upstream_port ||
            target_addr->sin_addr.s_addr == htonl(INADDR_LOOPBACK) ||
            flow.dst_ip == htonl(INADDR_LOOPBACK)) {
            LOG_DEBUG("[UDPSESSION_SUSPECT] sock=%llu client=%u.%u.%u.%u:%u flow_dst=%u.%u.%u.%u:%u target=%s:%u peer=%s:%u",
                (unsigned long long)s,
                flow.src_ip & 0xFF, (flow.src_ip >> 8) & 0xFF, (flow.src_ip >> 16) & 0xFF, (flow.src_ip >> 24) & 0xFF, ntohs(flow.src_port),
                flow.dst_ip & 0xFF, (flow.dst_ip >> 8) & 0xFF, (flow.dst_ip >> 16) & 0xFF, (flow.dst_ip >> 24) & 0xFF, ntohs(flow.dst_port),
                target_ip,
                ntohs(target_addr->sin_port),
                peer_ip,
                peer_port);
        }
        if (ntohs(flow.dst_port) == 53) {
            LOG_WARN("[DNSSTAT] direct_udp_session target=%s:%u local=%s:%u vport=%u",
                target_ip,
                ntohs(target_addr->sin_port),
                local_ip,
                ntohs(actual_local.sin_port),
                ntohs(client_addr->sin_port));
        }

        WorkerPool::instance().add_socket(s, [this, s](char* b, int l, const sockaddr_in* f) {
            this->on_remote_data(s, b, l, f);
        }, nullptr, true, nullptr, CONCURRENT_READ_COUNT, "proxy_udp_remote");
        
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
                g_udp_dns_counters.dns_direct_failures.fetch_add(1, std::memory_order_relaxed);
                LOG_DEBUG("[DNS] Failed to parse direct DNS response.");
            }
            else {
                g_udp_dns_counters.dns_direct_responses.fetch_add(1, std::memory_order_relaxed);
                if (res.rcode == 0 && !res.addresses.empty()) {
                    std::string ips;
                    for (size_t i = 0; i < res.addresses.size(); ++i) {
                        ips += res.addresses[i];
                        if (i < res.addresses.size() - 1) ips += ", ";
                    }
                    LOG_DEBUG("[DNS] Resolved '%s' to [%s] via DIRECT.", res.qname.c_str(), ips.c_str());

                    // Cache only A records. Other qtypes, such as HTTPS(65),
                    // must not be answered from an A-record cache entry.
                    if (res.qtype == 1) {
                        uint32_t first_ip = 0;
                        inet_pton(AF_INET, res.addresses[0].c_str(), &first_ip);
                        uint32_t cache_ttl = clamp_dns_cache_ttl(res.min_ttl);
                        DnsProbeTracker::instance().put_many(res.addresses, res.qname, cache_ttl);
                        DnsCache::instance().put(res.qname, first_ip, cache_ttl);
                        LOG_DEBUG("[DNS] Cached '%s' for %u seconds via DIRECT.", res.qname.c_str(), cache_ttl);
                    }
                }
                else if (res.rcode != 0) {
                    g_udp_dns_counters.dns_direct_failures.fetch_add(1, std::memory_order_relaxed);
                    LOG_DEBUG("[DNS] Failed to resolve '%s' via DIRECT. RCODE: %d", res.qname.c_str(), res.rcode);
                }
                else {
                    LOG_DEBUG("[DNS] Received response for '%s' via DIRECT (RCODE: 0, no A records).", res.qname.c_str());
                }
            }
        }
        // --- End of DNS Logging ---

        FlowKey flow = {};
        sockaddr_in client_addr = {};
        bool found = false;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_socket_to_flow.find(s);
            if (it != m_socket_to_flow.end()) {
                flow = it->second;
                auto sess_it = m_sessions.find(flow);
                if (sess_it != m_sessions.end()) {
                    Session& session = sess_it->second;
                    client_addr = session.client_addr;
                    session.last_access = GetTickCount64();
                    session.rx_packets++;
                    session.rx_bytes += (uint64_t)len;
                    if (!session.first_response_logged) {
                        session.first_response_logged = true;
                        uint64_t latency_ms = session.last_access - session.first_tx_time;
                        LOG_DEBUG("[UDPSTAT] first_response ip=%u.%u.%u.%u:%u latency_ms=%llu tx_pkts=%u rx_pkts=%u tx_bytes=%llu rx_bytes=%llu sessions=%zu",
                            flow.dst_ip & 0xFF, (flow.dst_ip >> 8) & 0xFF, (flow.dst_ip >> 16) & 0xFF, (flow.dst_ip >> 24) & 0xFF, ntohs(flow.dst_port),
                            (unsigned long long)latency_ms,
                            session.tx_packets,
                            session.rx_packets,
                            (unsigned long long)session.tx_bytes,
                            (unsigned long long)session.rx_bytes,
                            m_sessions.size());
                    }
                    found = true;
                }
            }
        }

        if (!found) {
            LOG_DEBUG("[UDP-IN] Dropping response from %s:%d because no matching UDP flow exists",
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
            WorkerPool::instance().read_async(s);
            return;
        }

        LOG_DEBUG("[UDP-IN] Received packet for flow %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u",
            flow.dst_ip & 0xFF, (flow.dst_ip >> 8) & 0xFF, (flow.dst_ip >> 16) & 0xFF, (flow.dst_ip >> 24) & 0xFF, ntohs(flow.dst_port),
            flow.src_ip & 0xFF, (flow.src_ip >> 8) & 0xFF, (flow.src_ip >> 16) & 0xFF, (flow.src_ip >> 24) & 0xFF, ntohs(flow.src_port));

        bool close_after_response = found && (ntohs(flow.dst_port) == 53);

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

        if (close_after_response) {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_sessions.find(flow);
            if (it != m_sessions.end() && it->second.sock == s) {
                remove_session_locked(it);
                return;
            }
        }
        
        WorkerPool::instance().read_async(s);
    }

    uint64_t timeout_for_flow(const FlowKey& flow) const {
        if (ntohs(flow.dst_port) == 53) return DNS_TIMEOUT_MS;
        if (ntohs(flow.dst_port) == 123) return SHORT_UDP_TIMEOUT_MS;
        return UDP_TIMEOUT_MS;
    }

    uint64_t no_response_timeout_for_session(const FlowKey& flow, const Session& session) const {
        if (session.rx_packets != 0) return 0;
        uint16_t dport = ntohs(flow.dst_port);
        if (dport == 53) return DNS_NO_RESPONSE_TIMEOUT_MS;
        if (dport == 123) return NTP_NO_RESPONSE_TIMEOUT_MS;
        if (m_sessions.size() >= UDP_PRESSURE_SESSION_COUNT) return UDP_NO_RESPONSE_PRESSURE_TIMEOUT_MS;
        return UDP_NO_RESPONSE_TIMEOUT_MS;
    }

    uint64_t timeout_for_session(const FlowKey& flow, const Session& session, uint64_t now) const {
        uint64_t no_response_timeout = no_response_timeout_for_session(flow, session);
        if (no_response_timeout != 0 && now - session.first_tx_time > no_response_timeout) {
            return 1;
        }
        return timeout_for_flow(flow);
    }

    void remove_session_locked(SessionMap::iterator it) {
        SOCKET s = it->second.sock;
        m_socket_to_flow.erase(s);
        WorkerPool::instance().remove_socket(s);
        m_sessions.erase(it);
    }

    void cleanup_sessions(uint64_t now, bool aggressive = false) {
        size_t cleaned = 0;
        for (auto it = m_sessions.begin(); it != m_sessions.end(); ) {
            uint64_t timeout = aggressive ? AGGRESSIVE_TIMEOUT_MS : timeout_for_session(it->first, it->second, now);
            uint64_t no_response_timeout = no_response_timeout_for_session(it->first, it->second);
            bool no_response_expired = no_response_timeout != 0 &&
                now - it->second.first_tx_time > no_response_timeout;
            if (no_response_expired || now - it->second.last_access > timeout) {
                auto current = it++;
                remove_session_locked(current);
                cleaned++;
            } else {
                ++it;
            }
        }
        if (cleaned > 0) {
            LOG_DEBUG("[UDP] Cleanup removed %zu sessions, remaining=%zu", cleaned, m_sessions.size());
        }
    }

public:
    void log_global_stats() {
        struct DestStat {
            uint32_t ip;
            uint16_t port;
            size_t sessions = 0;
            size_t no_response = 0;
            uint64_t tx_packets = 0;
            uint64_t rx_packets = 0;
            uint64_t tx_bytes = 0;
            uint64_t rx_bytes = 0;
        };

        size_t sessions = 0;
        size_t dns = 0;
        size_t quic = 0;
        size_t no_response = 0;
        size_t stale_no_response = 0;
        size_t loopback_2080 = 0;
        uint64_t tx_packets = 0;
        uint64_t rx_packets = 0;
        uint64_t tx_bytes = 0;
        uint64_t rx_bytes = 0;
        uint64_t max_age_ms = 0;
        uint64_t max_idle_ms = 0;
        uint64_t now = GetTickCount64();
        std::unordered_map<uint64_t, DestStat> dest_stats;

        uint32_t upstream_nbo = 0;
        inet_pton(AF_INET, g_config.upstream_ip.c_str(), &upstream_nbo);

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            sessions = m_sessions.size();
            for (const auto& kv : m_sessions) {
                const FlowKey& flow = kv.first;
                const Session& session = kv.second;
                uint16_t dport = ntohs(flow.dst_port);
                uint64_t dest_key = ((uint64_t)flow.dst_ip << 16) | flow.dst_port;
                DestStat& dest = dest_stats[dest_key];
                dest.ip = flow.dst_ip;
                dest.port = flow.dst_port;
                dest.sessions++;
                dest.tx_packets += session.tx_packets;
                dest.rx_packets += session.rx_packets;
                dest.tx_bytes += session.tx_bytes;
                dest.rx_bytes += session.rx_bytes;
                if (dport == 53) dns++;
                if (dport == 443) quic++;
                if (flow.dst_ip == upstream_nbo && dport == g_config.upstream_port) loopback_2080++;
                if (session.rx_packets == 0) {
                    no_response++;
                    dest.no_response++;
                    if (now - session.first_tx_time > 5000) stale_no_response++;
                }
                tx_packets += session.tx_packets;
                rx_packets += session.rx_packets;
                tx_bytes += session.tx_bytes;
                rx_bytes += session.rx_bytes;
                uint64_t age = now - session.first_tx_time;
                uint64_t idle = now - session.last_access;
                if (age > max_age_ms) max_age_ms = age;
                if (idle > max_idle_ms) max_idle_ms = idle;
            }
        }

        LOG_WARN("[UDPSTATG] sessions=%zu dns=%zu quic=%zu no_response=%zu stale_no_response=%zu loopback_2080=%zu tx_pkts=%llu rx_pkts=%llu tx_bytes=%llu rx_bytes=%llu max_age_ms=%llu max_idle_ms=%llu pressure_drop=%llu dns_q=%llu dns_cache=%llu dns_aaaa=%llu dns_dot_q=%llu dns_dot_resp=%llu dns_dot_fail=%llu dns_dot_nxdomain=%llu dns_dot_rcode_fail=%llu dns_direct_q=%llu dns_direct_resp=%llu dns_direct_fail=%llu",
            sessions,
            dns,
            quic,
            no_response,
            stale_no_response,
            loopback_2080,
            (unsigned long long)tx_packets,
            (unsigned long long)rx_packets,
            (unsigned long long)tx_bytes,
            (unsigned long long)rx_bytes,
            (unsigned long long)max_age_ms,
            (unsigned long long)max_idle_ms,
            (unsigned long long)g_udp_pressure_drops.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_queries.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_cache_hits.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_aaaa_blocked.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_dot_queries.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_dot_responses.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_dot_failures.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_dot_nxdomain.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_dot_rcode_failures.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_direct_queries.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_direct_responses.load(std::memory_order_relaxed),
            (unsigned long long)g_udp_dns_counters.dns_direct_failures.load(std::memory_order_relaxed));

        if (!dest_stats.empty()) {
            std::vector<DestStat> top;
            top.reserve(dest_stats.size());
            for (const auto& kv : dest_stats) {
                top.push_back(kv.second);
            }
            std::sort(top.begin(), top.end(), [](const DestStat& a, const DestStat& b) {
                if (a.sessions != b.sessions) return a.sessions > b.sessions;
                if (a.no_response != b.no_response) return a.no_response > b.no_response;
                return a.tx_packets > b.tx_packets;
            });

            std::string summary;
            size_t limit = std::min<size_t>(8, top.size());
            for (size_t i = 0; i < limit; ++i) {
                char ip[INET_ADDRSTRLEN] = "unknown";
                inet_ntop(AF_INET, &top[i].ip, ip, sizeof(ip));
                char item[256];
                snprintf(item, sizeof(item), "%s:%u s=%zu nr=%zu txp=%llu rxp=%llu txb=%llu rxb=%llu",
                    ip,
                    ntohs(top[i].port),
                    top[i].sessions,
                    top[i].no_response,
                    (unsigned long long)top[i].tx_packets,
                    (unsigned long long)top[i].rx_packets,
                    (unsigned long long)top[i].tx_bytes,
                    (unsigned long long)top[i].rx_bytes);
                if (!summary.empty()) summary += " | ";
                summary += item;
            }
            LOG_WARN("[UDPDEST] top=%s", summary.c_str());
        }
    }

private:
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
    SessionMap m_sessions;
    std::unordered_map<SOCKET, FlowKey> m_socket_to_flow;
    uint64_t m_last_cleanup;
    static constexpr uint64_t DNS_TIMEOUT_MS = 10000;
    static constexpr uint64_t SHORT_UDP_TIMEOUT_MS = 30000;
    static constexpr uint64_t UDP_TIMEOUT_MS = 60000;
    static constexpr uint64_t AGGRESSIVE_TIMEOUT_MS = 15000;
    static constexpr uint64_t DNS_NO_RESPONSE_TIMEOUT_MS = 3000;
    static constexpr uint64_t NTP_NO_RESPONSE_TIMEOUT_MS = 5000;
    static constexpr uint64_t UDP_NO_RESPONSE_TIMEOUT_MS = 8000;
    static constexpr uint64_t UDP_NO_RESPONSE_PRESSURE_TIMEOUT_MS = 3000;
    static constexpr size_t UDP_PRESSURE_SESSION_COUNT = 128;
    static constexpr uint64_t CLEANUP_INTERVAL_MS = 2000;
    static constexpr size_t MAX_SESSIONS = 512;
};

static UdpProxyManager g_udp_manager;

void UdpProxy::initialize() {
    g_udp_manager.initialize();
}

void UdpProxy::shutdown() {
    g_udp_manager.shutdown();
}

void UdpProxy::log_global_stats() {
    g_udp_manager.log_global_stats();
}

void UdpProxy::handle_client_data(SOCKET listener_socket, const char* data, int len, const sockaddr_in* client_addr, const OriginalDestination* dest) {
    g_udp_manager.handle_data(listener_socket, data, len, client_addr, dest);
}
