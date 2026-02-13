#pragma once

#include <winsock2.h>
#include <cstdint>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <optional>

struct OriginalDestination {
    uint32_t ip;
    uint16_t port;
    uint32_t original_client_ip;

    OriginalDestination() : ip(0), port(0), original_client_ip(0) {}
    OriginalDestination(uint32_t i, uint16_t p, uint32_t oc) 
        : ip(i), port(p), original_client_ip(oc) {}
};

class NatManager {
public:
    static NatManager& instance();

    static uint64_t make_key(uint32_t ip, uint16_t port) {
        return (static_cast<uint64_t>(ip) << 16) | port;
    }

    // TCP Mappings (Connection-based)
    void create_tcp_mapping(uint64_t key, const OriginalDestination& dest);
    void remove_tcp_mapping(uint64_t key);
    
    // UDP Mappings (Flow-based with timeout)
    void create_or_update_udp_mapping(uint64_t key, const OriginalDestination& dest);
    
    // Generic lookup
    std::optional<OriginalDestination> get_mapping(uint64_t key);

private:
    NatManager();
    ~NatManager();

    std::unordered_map<uint64_t, OriginalDestination> m_tcp_map;
    std::unordered_map<uint64_t, std::pair<OriginalDestination, uint64_t>> m_udp_map;
    
    mutable std::shared_mutex m_tcp_mtx;
    mutable std::shared_mutex m_udp_mtx;
};
