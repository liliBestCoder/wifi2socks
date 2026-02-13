#pragma once

#include <winsock2.h>
#include <cstdint>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <optional>

struct ClientKey {
    uint32_t ip;
    uint16_t port;

    bool operator==(const ClientKey& o) const {
        return ip == o.ip && port == o.port;
    }
};

struct ClientKeyHash {
    size_t operator()(const ClientKey& k) const {
        return std::hash<uint32_t>{}(k.ip) ^ (std::hash<uint16_t>{}(k.port) << 1);
    }
};

struct OriginalDestination {
    uint32_t ip;
    uint16_t port;
};

class NatManager {
public:
    static NatManager& instance();

    // TCP Mappings (Connection-based)
    void create_tcp_mapping(const ClientKey& key, const OriginalDestination& dest);
    void remove_tcp_mapping(const ClientKey& key);
    
    // UDP Mappings (Flow-based with timeout)
    void create_or_update_udp_mapping(const ClientKey& key, const OriginalDestination& dest);
    
    // Generic lookup
    std::optional<OriginalDestination> get_mapping(const ClientKey& key);

private:
    NatManager();
    ~NatManager();

    std::unordered_map<ClientKey, OriginalDestination, ClientKeyHash> m_tcp_map;
    std::unordered_map<ClientKey, std::pair<OriginalDestination, uint64_t>, ClientKeyHash> m_udp_map;
    
    mutable std::shared_mutex m_tcp_mtx;
    mutable std::shared_mutex m_udp_mtx;
};
