#pragma once
#include <cstdint>
#include <unordered_map>
#include <utility>
#include <mutex>
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

struct PairHash {
    size_t operator()(const std::pair<uint32_t, uint16_t>& p) const {
        return std::hash<uint32_t>{}(p.first) ^ (std::hash<uint16_t>{}(p.second) << 1);
    }
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
    std::unordered_map<std::pair<uint32_t, uint16_t>, NatEntry, PairHash> m_table;
    std::mutex m_mtx;
};
