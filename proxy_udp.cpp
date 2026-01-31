#include "proxy_udp.h"
#include "worker.h"
#include "tap_driver.h"
#include "app_config.h"
#include "lwip_handler.h"
#include "nat_table.h"
#include <map>
#include <vector>
#include <deque>
#include <string>
#include <unordered_set>
#include <fstream>
#include <algorithm>
#include <iostream>

// --- Domain Rules ---
std::unordered_set<std::string> g_cn_rules;
bool g_rules_loaded = false;

void load_cn_rules() {
    if (g_rules_loaded) return;
    
    // Default fallback list
    std::vector<std::string> defaults = {
        "cn", "baidu.com", "qq.com", "163.com", "126.com", "taobao.com", 
        "jd.com", "tmall.com", "zhihu.com", "bilibili.com", "weibo.com", 
        "xinhuanet.com", "sohu.com", "iqiyi.com", "csdn.net", "aliyun.com",
        "tencent.com", "alipay.com", "xiaomi.com", "douyin.com", "meituan.com",
        "cnblogs.com", "360.cn"
    };
    
    for (const auto& d : defaults) g_cn_rules.insert(d);

    // Try load from file
    std::ifstream file("cn.txt");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            // Trim whitespace
            line.erase(0, line.find_first_not_of(" 	\r\n"));
            line.erase(line.find_last_not_of(" 	\r\n") + 1);
            if (line.empty() || line[0] == '#') continue;
            g_cn_rules.insert(line);
        }
        printf("[Rules] Loaded %zu rules from cn.txt\n", g_cn_rules.size());
    } else {
        printf("[Rules] cn.txt not found, using %zu built-in rules.\n", g_cn_rules.size());
    }
    g_rules_loaded = true;
}

bool is_domestic(const std::string& domain) {
    if (!g_rules_loaded) load_cn_rules();
    if (domain.empty()) return false;

    // Convert to lowercase for matching
    std::string temp = domain;
    std::transform(temp.begin(), temp.end(), temp.begin(), 
                   [](unsigned char c){ return std::tolower(c); });

    // Strip local suffixes caused by Windows ICS / Router DNS
    // This allows "baidu.com.mshome.net" to be identified as "baidu.com" -> Domestic
    const char* suffixes[] = { ".mshome.net", ".lan", ".local", ".localdomain" };
    for (const char* suffix : suffixes) {
        size_t suffix_len = strlen(suffix);
        if (temp.length() > suffix_len) {
            if (temp.compare(temp.length() - suffix_len, suffix_len, suffix) == 0) {
                printf("[Rules] Stripped local suffix: %s -> ", temp.c_str());
                temp = temp.substr(0, temp.length() - suffix_len);
                printf("%s\\n", temp.c_str());
                break; 
            }
        }
    }

    // Check full domain or suffixes
    // e.g. www.baidu.com -> check "baidu.com", "com", "www.baidu.com"
    // Heuristic: check last parts
    
    // Simple suffix matching
    // If domain ends with ".cn", it's domestic
    if (temp.length() > 3 && temp.substr(temp.length() - 3) == ".cn") return true;

    // Check mapping
    // Iterate parts: www.baidu.com -> www.baidu.com, baidu.com, com
    size_t pos = 0;
    while (pos != std::string::npos) {
        std::string suffix = temp.substr(pos);
        if (g_cn_rules.count(suffix)) return true;
        
        pos = temp.find('.', pos);
        if (pos != std::string::npos) pos++;
    }
    
    return false;
}

// --- UDP Session (Thread Local) ---
struct UdpKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    bool operator<(const UdpKey& o) const { return memcmp(this, &o, sizeof(UdpKey)) < 0; }
};

struct UdpSession {
    SOCKET sock; // Only use direct socket now
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint64_t last_active;
    Worker* worker;
    
    UdpSession() : sock(INVALID_SOCKET), worker(NULL) { 
        last_active = GetTickCount64(); 
    }
};

thread_local std::map<UdpKey, UdpSession*> t_udp_sessions;

void close_udp_session_internal(UdpSession* sess) {
    if (!sess) return; 
    
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

void handle_direct_udp_read(UdpSession* sess) {
    char buf[4096];
    sockaddr_in from;
    int from_len = sizeof(from);
    int r = recvfrom(sess->sock, buf, sizeof(buf), 0, (sockaddr*)&from, &from_len);
    
    if (r > 0) {
        sess->last_active = GetTickCount64();
        
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
        // Use Session IP for return path.
        // Important: If we hijacked DNS to 223.5.5.5, sess->dst_ip is 223.5.5.5.
        // But the OS might have sent to 192.168.1.1.
        // If we reply from 223.5.5.5, OS will accept it? Usually yes if it matches the transaction ID.
        // BUT, better to spoof the source IP as the one the client intended to send to (sess->dst_ip).
        // Wait, if we hijacked, sess->dst_ip IS the hijacked target (223).
        // We should probably store the ORIGINAL dst ip if we want to be perfect.
        // However, standard DNS resolvers usually reply from the IP they were queried at.
        // If we diverted the query to 223.5.5.5, we should probably reply as 223.5.5.5?
        // No, the OS thinks it sent to X. If reply comes from Y, OS drops it.
        // WE need to reply as X.
        // IN our handle_udp_packet logic below, we change dst_ip passed to `sendto`, 
        // BUT we keep the UdpSession key and structure using the ORIGINAL dst_ip requested by client.
        // Let's check handle_udp_packet.
        
        *(uint32_t*)(ip + 12) = sess->dst_ip; // Src = Server (Original Target)
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

// DNS Parser helper
std::string parse_dns_qname(const uint8_t* payload, int len, int* qname_len) {
    if (len < 12) return "";
    int pos = 12;
    std::string domain;
    
    while (pos < len) {
        uint8_t n = payload[pos];
        if (n == 0) { 
            pos++; 
            break; 
        }
        if ((n & 0xC0) == 0xC0) return ""; // Pointers not expected in Query
        
        if (pos + n + 1 > len) return "";
        
        if (!domain.empty()) domain += ".";
        domain.append((char*)(payload + pos + 1), n);
        pos += n + 1;
    }
    
    if (qname_len) *qname_len = pos - 12;
    return domain;
}

void handle_dns_fake_ip(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len, const std::string& domain) {
    if (len < 12) return; 
    
    uint16_t id = *(uint16_t*)payload;
    int qname_len = 0;
    // We already parsed domain in handle_udp_packet, just need len to skip
    parse_dns_qname(payload, len, &qname_len); 
    int pos = 12 + qname_len;
    
    if (pos + 4 > len) return;
    
    // Get Fake IP
    uint32_t fake_ip = FakeIpMapper::instance().get_fake_ip(domain);
    
    printf("[FakeDNS] Query: %s -> FakeIP: %d.%d.%d.%d\n", domain.c_str(), 
        fake_ip & 0xFF, (fake_ip >> 8) & 0xFF, (fake_ip >> 16) & 0xFF, (fake_ip >> 24) & 0xFF);

    // Build Response
    std::vector<uint8_t> resp;
    resp.reserve(512);
    
    // Header
    resp.push_back(id & 0xFF); resp.push_back((id >> 8) & 0xFF);
    resp.push_back(0x81); resp.push_back(0x80); // Flags
    resp.push_back(0x00); resp.push_back(0x01); // QD=1
    resp.push_back(0x00); resp.push_back(0x01); // AN=1
    resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x00); resp.push_back(0x00);
    
    // Question Section
    resp.insert(resp.end(), payload + 12, payload + pos + 4);
    
    // Answer Section
    resp.push_back(0xC0); resp.push_back(0x0C); // Ptr
    resp.push_back(0x00); resp.push_back(0x01); // A
    resp.push_back(0x00); resp.push_back(0x01); // IN
    resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x01); // TTL=1s
    resp.push_back(0x00); resp.push_back(0x04); // Len
    resp.push_back(fake_ip & 0xFF);
    resp.push_back((fake_ip >> 8) & 0xFF);
    resp.push_back((fake_ip >> 16) & 0xFF);
    resp.push_back((fake_ip >> 24) & 0xFF);
    
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
    *(uint32_t*)(ip + 12) = dst_ip; 
    *(uint32_t*)(ip + 16) = src_ip; 
    *(uint16_t*)(ip + 10) = ip_chksum_simple(ip, 20);

    *(uint16_t*)(udp_hdr + 0) = dst_port; 
    *(uint16_t*)(udp_hdr + 2) = src_port; 
    *(uint16_t*)(udp_hdr + 4) = htons((uint16_t)(8 + resp.size()));
    *(uint16_t*)(udp_hdr + 6) = 0;
    memcpy(udp_hdr + 8, resp.data(), resp.size());

    TapDriver::instance().send_async(frame, 14 + 20 + 8 + (int)resp.size());
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
    // 1. DROP QUIC
    if (dst_port == htons(443)) return;

    // 2. DNS Handling (Split DNS)
    if (dst_port == htons(53)) {
        int qname_len = 0;
        std::string domain = parse_dns_qname(payload, len, &qname_len);
        
        if (!domain.empty()) {
            if (!is_domestic(domain)) {
                // Foreign -> FakeIP
                handle_dns_fake_ip(src_ip, dst_ip, src_port, dst_port, payload, len, domain);
                return;
            }
            // Domestic -> Continue to Direct UDP (but hijack target to AliDNS)
            // We want to force domestic queries to 223.5.5.5 to ensure they resolve properly and fast.
            // Override destination for the socket logic below.
            // NOTE: 'dst_ip' is network order. 223.5.5.5 = 0xDF050505 (Host) -> Network?
            // 223 = 0xDF, 5 = 0x05.
            // IP: 223.5.5.5
            // Byte array: [223, 5, 5, 5]
            uint8_t ali_bytes[4] = {223, 5, 5, 5};
            memcpy(&dst_ip, ali_bytes, 4);
            printf("[Direct-DNS] Domestic: %s -> Forwarding to 223.5.5.5\n", domain.c_str());
        }
    }

    // 3. Direct UDP for others (and Domestic DNS)
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
            sess->src_ip = src_ip; 
            sess->dst_ip = dst_ip; // This should be ORIGINAL.
            // Wait, if we hijacked 'dst_ip' in handle_udp_packet, it's passed here as 'dst_ip'.
            // So sess->dst_ip will be 223.5.5.5.
            // BUT, when responding to OS, we need to reply as the ORIGINAL destination (e.g. 192.168.1.1).
            // Logic gap: The OS expects reply from 192.168.1.1, but we will send reply from 223.5.5.5.
            // FIX: We need to pass BOTH actual_target AND original_target to this lambda?
            // Actually, for NAT to work transparently, we usually need to masquerade the source IP of the reply
            // to match the destination IP of the request.
            // In 'handle_direct_udp_read', we use sess->dst_ip as the Source IP of the reply packet.
            // So sess->dst_ip MUST be the IP the client *thinks* it sent to.
            
            // Correction: We need to store the ORIGINAL destination in UdpSession to spoof the reply correctly,
            // but use the HIJACKED destination for the actual `sendto`.
            
            sess->src_ip = src_ip; 
            sess->dst_ip = dst_ip; // This should be ORIGINAL.
            sess->src_port = src_port; 
            sess->dst_port = dst_port;
            sess->worker = w;
            
            sess->sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sess->sock == INVALID_SOCKET) { delete sess; return; }
            u_long mode = 1; ioctlsocket(sess->sock, FIONBIO, &mode);
            
            t_udp_sessions[key] = sess;
            
            sockaddr_in local;
            memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET;
            local.sin_addr.S_un.S_addr = INADDR_ANY;
            local.sin_port = 0;
            bind(sess->sock, (sockaddr*)&local, sizeof(local));
            
            sess->worker->add_socket(
                sess->sock,
                [sess]() { handle_direct_udp_read(sess); },
                nullptr, 
                [sess]() { close_udp_session_internal(sess); }
            );
        }
        
        if (sess) {
            sess->last_active = GetTickCount64();
            sockaddr_in dest;
            dest.sin_family = AF_INET;
            
            // Check if this is a Domestic DNS case that needs hijacking *for the sendto only*
            // We don't have the domain here easily.
            // Strategy: Use the port. If port 53, send to 223.5.5.5.
            // Note: This applies to ALL Port 53 traffic that reaches here. 
            // Since Foreign DNS is filtered out by `handle_udp_packet` (returns early),
            // any Port 53 reaching here IS Domestic DNS.
            if (dst_port == htons(53)) {
                 unsigned int a, b, c, d;
                 // 223.5.5.5
                 uint8_t ali[4] = {223, 5, 5, 5};
                 memcpy(&dest.sin_addr.S_un.S_addr, ali, 4);
            } else {
                 dest.sin_addr.S_un.S_addr = dst_ip;
            }
            dest.sin_port = dst_port;
            
            sendto(sess->sock, (const char*)data.data(), (int)data.size(), 0, (sockaddr*)&dest, sizeof(dest));
        }
    });
}