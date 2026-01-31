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

// Singleton for FakeIP Mapping (Domain <-> 198.18.x.x)
class FakeIpMapper {
public:
    static FakeIpMapper& instance();
    
    // Allocate (or reuse) a Fake IP for a domain
    uint32_t get_fake_ip(const std::string& domain);
    
    // Lookup domain by Fake IP
    std::string get_domain(uint32_t ip);

    bool is_fake_ip(uint32_t ip);

private:
    std::map<std::string, uint32_t> m_domain_to_ip;
    std::map<uint32_t, std::string> m_ip_to_domain;
    std::mutex m_mtx;
    uint32_t m_next_ip = 1; 
};
