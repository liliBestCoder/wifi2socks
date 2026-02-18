#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>

class DnsCache {
public:
    static DnsCache& instance() {
        static DnsCache inst;
        return inst;
    }

    void put(const std::string& domain, uint32_t ip, uint32_t ttl) {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_cache[domain] = { ip, std::chrono::steady_clock::now() + std::chrono::seconds(ttl) };
    }

    uint32_t get(const std::string& domain) {
        std::lock_guard<std::mutex> lock(m_mtx);
        auto it = m_cache.find(domain);
        if (it != m_cache.end()) {
            if (std::chrono::steady_clock::now() < it->second.expiry) {
                return it->second.ip;
            } else {
                m_cache.erase(it);
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
    std::mutex m_mtx;
};