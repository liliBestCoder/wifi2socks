#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <chrono>

class DnsCache {
public:
    static DnsCache& instance() {
        static DnsCache inst;
        return inst;
    }

    void put(const std::string& domain, uint32_t ip, uint32_t ttl) {
        std::unique_lock<std::shared_mutex> lock(m_mtx);
        m_cache[domain] = { ip, std::chrono::steady_clock::now() + std::chrono::seconds(ttl) };
    }

    uint32_t get(const std::string& domain) {
        std::shared_lock<std::shared_mutex> lock(m_mtx);
        auto it = m_cache.find(domain);
        if (it != m_cache.end()) {
            if (std::chrono::steady_clock::now() < it->second.expiry) {
                return it->second.ip;
            }
        }
        return 0;
    }

private:
    DnsCache() {}
    
    struct Entry {
        uint32_t ip;
        std::chrono::steady_clock::time_point expiry;
    };
    
    std::unordered_map<std::string, Entry> m_cache;
    std::shared_mutex m_mtx;
};