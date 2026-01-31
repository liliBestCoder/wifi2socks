#include "nat_table.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <algorithm>
#include <vector>
#include <cctype>

NatTable& NatTable::instance() {
    static NatTable instance;
    return instance;
}

void NatTable::set(uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    std::lock_guard<std::mutex> lock(m_mtx);
    NatEntry entry;
    entry.original_dst_ip = dst_ip;
    entry.original_dst_port = dst_port;
    entry.last_active = GetTickCount64();
    m_table[src_port] = entry;
}

NatEntry NatTable::get(uint16_t src_port) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_table.find(src_port);
    if (it != m_table.end()) {
        it->second.last_active = GetTickCount64();
        return it->second;
    }
    return {0, 0, 0};
}

void NatTable::cleanup(uint64_t timeout_ms) {
    std::lock_guard<std::mutex> lock(m_mtx);
    uint64_t now = GetTickCount64();
    for (auto it = m_table.begin(); it != m_table.end(); ) {
        if (now - it->second.last_active > timeout_ms) {
            it = m_table.erase(it);
        } else {
            ++it;
        }
    }
}

// --- FakeIpMapper ---

FakeIpMapper& FakeIpMapper::instance() {
    static FakeIpMapper inst;
    return inst;
}

uint32_t FakeIpMapper::get_fake_ip(const std::string& domain) {
    std::lock_guard<std::mutex> lock(m_mtx);
    
    // Check if domain exists
    auto it = m_domain_to_ip.find(domain);
    if (it != m_domain_to_ip.end()) {
        return it->second;
    }

    // Allocate new IP
    // Range 198.18.0.0/15
    // Use a counter starting at 1
    uint32_t c = m_next_ip++;
    if (m_next_ip > 0xFFFE) { // Simple wrap around
        m_next_ip = 1;
    }

    // IP = 198.18.(c>>8).(c&0xFF)
    // Construct in Network Byte Order
    uint8_t bytes[4];
    bytes[0] = 198;
    bytes[1] = 18;
    bytes[2] = (uint8_t)((c >> 8) & 0xFF);
    bytes[3] = (uint8_t)(c & 0xFF);
    
    uint32_t ip;
    memcpy(&ip, bytes, 4);

    // Clean reverse map if overwritten
    if (m_ip_to_domain.count(ip)) {
        std::string old = m_ip_to_domain[ip];
        m_domain_to_ip.erase(old);
    }

    m_domain_to_ip[domain] = ip;
    m_ip_to_domain[ip] = domain;
    
    return ip;
}

std::string FakeIpMapper::get_domain(uint32_t ip) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_ip_to_domain.find(ip);
    if (it != m_ip_to_domain.end()) {
        return it->second;
    }
    return "";
}

bool FakeIpMapper::is_fake_ip(uint32_t ip) {
    uint8_t* p = (uint8_t*)&ip;
    // Check if 198.18.x.x (Network Order, usually p[0] is first byte)
    // On Little Endian Windows, memory is [198, 18, x, x]
    return (p[0] == 198 && p[1] == 18);
}

// --- DomainRules ---

DomainRules& DomainRules::instance() {
    static DomainRules inst;
    return inst;
}

DomainRules::DomainRules() : m_loaded(false) {
    reload();
}

void DomainRules::reload() {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_cn_rules.clear();
    
    std::vector<std::string> defaults = {
        "baidu.com", "qq.com", "aliyun.com", "taobao.com", "jd.com", 
        "zhihu.com", "bilibili.com", "weibo.com", "xiaomi.com", "huawei.com",
        "163.com", "126.com", "douyin.com", "kuaishou.com", "360.cn",
        "csdn.net", "gitee.com", "oschina.net", "cn",
        "amemv.com", "zijieapi.com", "dutils.com", "volceapplog.com"
    };
    for(const auto& d : defaults) m_cn_rules.insert(d);

    std::ifstream file("cn.txt");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            // Simple trim
            while (!line.empty() && isspace((unsigned char)line.back())) line.pop_back();
            while (!line.empty() && isspace((unsigned char)line.front())) line.erase(0, 1);
            
            if (line.empty() || line[0] == '#') continue;
            m_cn_rules.insert(line);
        }
    }
    m_loaded = true;
}

bool DomainRules::is_domestic(const std::string& domain) {
    if (domain.empty()) return false;
    
    std::string temp = domain;
    std::transform(temp.begin(), temp.end(), temp.begin(), ::tolower);

    // Check strict .cn suffix
    if (temp.length() > 3 && temp.substr(temp.length() - 3) == ".cn") return true;

    // Check rules mapping
    std::lock_guard<std::mutex> lock(m_mtx);
    
    // Check full domain first
    if (m_cn_rules.count(temp)) return true;

    // Check suffixes
    size_t pos = 0;
    while ((pos = temp.find('.', pos)) != std::string::npos) {
        pos++; // Skip dot
        std::string suffix = temp.substr(pos);
        if (m_cn_rules.count(suffix)) return true;
    }
    
    return false;
}