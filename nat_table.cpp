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

// --- DnsCache ---

DnsCache& DnsCache::instance() {
    static DnsCache inst;
    return inst;
}

uint32_t DnsCache::get(const std::string& domain) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_cache.find(domain);
    if (it != m_cache.end()) {
        if (GetTickCount64() < it->second.expire_time) {
            return it->second.ip;
        } else {
            m_cache.erase(it); // Expired
        }
    }
    return 0;
}

void DnsCache::put(const std::string& domain, uint32_t ip, int ttl_sec) {
    std::lock_guard<std::mutex> lock(m_mtx);
    // Min TTL 60s, Max TTL 1 hour to keep it reasonably fresh
    if (ttl_sec < 60) ttl_sec = 60;
    if (ttl_sec > 3600) ttl_sec = 3600;
    
    DnsCacheEntry entry;
    entry.ip = ip;
    entry.expire_time = GetTickCount64() + (ttl_sec * 1000);
    m_cache[domain] = entry;
}

void DnsCache::cleanup() {
    std::lock_guard<std::mutex> lock(m_mtx);
    uint64_t now = GetTickCount64();
    for (auto it = m_cache.begin(); it != m_cache.end(); ) {
        if (now > it->second.expire_time) {
            it = m_cache.erase(it);
        } else {
            ++it;
        }
    }
}
