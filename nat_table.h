#pragma once
#include <cstdint>
#include <map>
#include <utility>
#include <mutex>
#include <unordered_set>
#include <string>
#include <vector>

struct NatEntry {
    uint32_t original_dst_ip;
    uint16_t original_dst_port;
    uint32_t src_ip;
    uint16_t src_port;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint64_t last_active;
};

// Singleton or global access to NAT table
class NatTable {
public:
    static NatTable& instance();
    
    void set(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, const uint8_t* src_mac = nullptr, const uint8_t* dst_mac = nullptr);
    NatEntry get(uint32_t src_ip, uint16_t src_port);
    NatEntry get_by_port(uint16_t local_src_port);
    
    // Cleanup old entries
    void cleanup(uint64_t timeout_ms);

private:
    std::map<std::pair<uint32_t, uint16_t>, NatEntry> m_table;
    std::mutex m_mtx;
};
