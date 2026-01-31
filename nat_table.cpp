#include "nat_table.h"
#include <winsock2.h>
#include <ws2tcpip.h>

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
    
    // Return existing if found
    auto it = m_domain_to_ip.find(domain);
    if (it != m_domain_to_ip.end()) {
        return it->second;
    }

    // Alloc new
    // 198.18.0.0/15
    // Use simple counter
    uint32_t c = m_next_ip++; 
    if (m_next_ip > 0xFFFF) { // Wrap around (65535 IPs)
        m_next_ip = 1;
    }

    // Construct IP 198.18.c_high.c_low
    // Network Byte Order: 198 (high), 18, c_high, c_low
    uint8_t bytes[4];
    bytes[0] = 198;
    bytes[1] = 18;
    bytes[2] = (c >> 8) & 0xFF;
    bytes[3] = c & 0xFF;
    
    uint32_t ip;
    memcpy(&ip, bytes, 4); // ip is now Network Order

    // Clean reverse mapping if overwriting
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
    // Check 198.18.x.x
    return (p[0] == 198 && p[1] == 18);
}
