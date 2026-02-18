#pragma once

// Essential system headers
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// Standard library headers for types and containers
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <optional>

// Forward declaration if Common.h is complex, or include it if it defines needed flags
#include "Common.h"

// Define OriginalDestination struct
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

    // Generate a unique key: IP (high 32 bits) | Port (low 16 bits)
    static uint64_t make_key(uint32_t ip, uint16_t port) {
        return ((uint64_t)ip << 16) | port;
    }

    void create_tcp_mapping(uint64_t key, const OriginalDestination& dest);
    void create_or_update_udp_mapping(uint64_t key, const OriginalDestination& dest);
    
    std::optional<OriginalDestination> get_mapping(uint64_t key);
    void remove_tcp_mapping(uint64_t key);

private:
    NatManager();
    ~NatManager();

    struct MappingEntry {
        OriginalDestination dest;
        uint64_t last_access;
    };

    static const int NUM_SHARDS = 16;
    struct Shard {
        std::shared_mutex mtx;
        std::unordered_map<uint64_t, MappingEntry> tcp_map;
        std::unordered_map<uint64_t, MappingEntry> udp_map;
        uint64_t last_cleanup_time = 0;
    };

    Shard m_shards[NUM_SHARDS];
    
    // Timeouts
    const uint64_t TCP_TIMEOUT_MS = 120000;
    const uint64_t UDP_TIMEOUT_MS = 60000;
};