#pragma once
#include <cstdint>
#include <map>
#include <mutex>
#include <unordered_set>
#include <string>
#include <vector>

struct NatEntry {
    uint32_t original_dst_ip;
    uint16_t original_dst_port;
    uint64_t last_active;
};

// Singleton or global access to NAT table
class NatTable {
public:
    static NatTable& instance();
    
    void set(uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);
    NatEntry get(uint16_t src_port);
    
    // Cleanup old entries
    void cleanup(uint64_t timeout_ms);

private:
    std::map<uint16_t, NatEntry> m_table;
    std::mutex m_mtx;
};

// Simple DNS Cache (Domain -> IP)
struct DnsCacheEntry {
    uint32_t ip; // Network Order
    uint64_t expire_time;
};

class DnsCache {
public:
    static DnsCache& instance();
    
    // Returns 0 if not found or expired
    uint32_t get(const std::string& domain);
    
    void put(const std::string& domain, uint32_t ip, int ttl_sec);
    
    void cleanup();

private:
    std::map<std::string, DnsCacheEntry> m_cache;
    std::mutex m_mtx;
};
