#pragma once
#include <cstdint>
#include <map>
#include <mutex>

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
