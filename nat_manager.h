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
#include <deque>
#include <atomic>

// Forward declaration if Common.h is complex, or include it if it defines needed flags
#include "Common.h"

// Define OriginalDestination struct
struct OriginalDestination {
    uint32_t ip;
    uint16_t port;
    uint32_t original_client_ip;
    uint32_t worker_id;

    OriginalDestination() : ip(0), port(0), original_client_ip(0), worker_id(0) {}
    OriginalDestination(uint32_t i, uint16_t p, uint32_t oc, uint32_t w = 0) 
        : ip(i), port(p), original_client_ip(oc), worker_id(w) {}
};

struct UdpKey4 {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;

    bool operator==(const UdpKey4& other) const {
        return src_ip == other.src_ip && src_port == other.src_port &&
               dst_ip == other.dst_ip && dst_port == other.dst_port;
    }
};

struct UdpKey4Hash {
    std::size_t operator()(const UdpKey4& k) const {
        std::size_t h1 = std::hash<uint32_t>{}(k.src_ip);
        std::size_t h2 = std::hash<uint16_t>{}(k.src_port);
        std::size_t h3 = std::hash<uint32_t>{}(k.dst_ip);
        std::size_t h4 = std::hash<uint16_t>{}(k.dst_port);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
    }
};

class NatManager {
public:
    static NatManager& instance();

    // Generate a unique key: IP (high 32 bits) | Port (low 16 bits)
    static uint64_t make_key(uint32_t ip, uint16_t port) {
        return ((uint64_t)ip << 16) | port;
    }

    void create_tcp_mapping(uint64_t key, const OriginalDestination& dest, uint32_t worker_id);
    void create_or_update_udp_mapping(const UdpKey4& key, const OriginalDestination& dest, uint32_t worker_id);
    
    // New: Virtual port management for UDP
    uint16_t allocate_udp_virtual_port(const UdpKey4& key, const OriginalDestination& dest);
    std::optional<UdpKey4> get_udp_key_by_virtual_port(uint16_t vport);

    std::optional<OriginalDestination> get_mapping(uint64_t key);
    std::optional<OriginalDestination> get_udp_mapping(const UdpKey4& key);
    void remove_tcp_mapping(uint64_t key);

    // Active maintenance
    void cleanup();

private:
    NatManager();
    ~NatManager();

    void cleanup_loop();
    std::thread m_cleanup_thread;
    std::atomic<bool> m_cleanup_running{ false };
    std::condition_variable m_cleanup_cv;
    std::mutex m_cleanup_mtx;

    struct MappingEntry {
        OriginalDestination dest;
        uint64_t last_access;
        UdpKey4 udp_key;
        uint16_t vport = 0; // Add virtual port reference
    };

    struct VPortEntry {
        UdpKey4 key;
        uint64_t last_access;
        bool active = false;
    };

    void cleanup_expired(uint64_t now);

    // Global structures (No more sharding)
    mutable std::shared_mutex m_global_mtx;
    std::unordered_map<uint64_t, MappingEntry> m_tcp_map;
    std::unordered_map<UdpKey4, MappingEntry, UdpKey4Hash> m_udp_map;
    std::unordered_map<uint16_t, VPortEntry> m_vport_to_udp;
    
    // Port Pool Management
    std::deque<uint16_t> m_free_vports;
    uint64_t m_last_cleanup_time = 0;

    const uint16_t VPORT_START = 5000;
    const uint16_t VPORT_END = 65000;
    
    // Timeouts
    const uint64_t TCP_TIMEOUT_MS = 300000;
    const uint64_t UDP_TIMEOUT_MS = 30000; 
};
