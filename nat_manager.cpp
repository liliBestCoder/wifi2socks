#include "nat_manager.h"
#include "logger.h"
#include "app_config.h"

// Implementation of NatManager

NatManager& NatManager::instance() {
    static NatManager inst;
    return inst;
}

NatManager::NatManager() {
    // Initialize the free port pool
    for (uint16_t port = VPORT_START; port <= VPORT_END; ++port) {
        m_free_vports.push_back(port);
    }
    LOG_INFO("[NAT] Initialized with %zu virtual ports", m_free_vports.size());
}

NatManager::~NatManager() {}

void NatManager::cleanup_expired(uint64_t now) {
    if (now - m_last_cleanup_time < 5000) return; // 5 second interval
    m_last_cleanup_time = now;

    size_t cleaned_udp = 0;
    // Cleanup UDP & VPorts (They MUST be cleaned together for consistency)
    for (auto it = m_vport_to_udp.begin(); it != m_vport_to_udp.end(); ) {
        if (now - it->second.last_access > UDP_TIMEOUT_MS) {
            // 1. Remove from forward map
            m_udp_map.erase(it->second.key);
            // 2. Return port to the free pool
            m_free_vports.push_back(it->first);
            // 3. Remove from reverse map
            it = m_vport_to_udp.erase(it);
            cleaned_udp++;
        }
        else {
            ++it;
        }
    }

    // Cleanup TCP
    size_t cleaned_tcp = 0;
    for (auto it = m_tcp_map.begin(); it != m_tcp_map.end(); ) {
        if (now - it->second.last_access > TCP_TIMEOUT_MS) {
            it = m_tcp_map.erase(it);
            cleaned_tcp++;
        }
        else {
            ++it;
        }
    }

    if (cleaned_udp > 0 || cleaned_tcp > 0) {
        LOG_DEBUG("[NAT] Cleanup: %zu UDP, %zu TCP mappings removed. Free ports: %zu", 
            cleaned_udp, cleaned_tcp, m_free_vports.size());
    }
}

void NatManager::create_tcp_mapping(uint64_t key, const OriginalDestination& dest, uint32_t worker_id) {
    std::unique_lock<std::shared_mutex> lock(m_global_mtx);
    uint64_t now = GetTickCount64();
    cleanup_expired(now);
    
    m_tcp_map[key] = { dest, now, {}, 0 };
    m_tcp_map[key].dest.worker_id = worker_id;
}

void NatManager::remove_tcp_mapping(uint64_t key) {
    std::unique_lock<std::shared_mutex> lock(m_global_mtx);
    m_tcp_map.erase(key);
}

void NatManager::create_or_update_udp_mapping(const UdpKey4& key, const OriginalDestination& dest, uint32_t worker_id) {
    std::unique_lock<std::shared_mutex> lock(m_global_mtx);
    uint64_t now = GetTickCount64();
    cleanup_expired(now);
    
    auto it = m_udp_map.find(key);
    if (it != m_udp_map.end()) {
        it->second.last_access = now;
        it->second.dest.worker_id = worker_id;
        if (it->second.vport != 0) {
            m_vport_to_udp[it->second.vport].last_access = now;
        }
    } else {
        // Note: This function doesn't allocate vports. 
        // allocate_udp_virtual_port must be called first or instead.
        MappingEntry entry = { dest, now, key, 0 };
        entry.dest.worker_id = worker_id;
        m_udp_map[key] = entry;
    }
}

uint16_t NatManager::allocate_udp_virtual_port(const UdpKey4& key, const OriginalDestination& dest) {
    std::unique_lock<std::shared_mutex> lock(m_global_mtx);
    uint64_t now = GetTickCount64();
    
    // Always try to cleanup if pool is getting low
    if (m_free_vports.empty() || (now - m_last_cleanup_time > 5000)) {
        cleanup_expired(now);
    }

    // 1. Check if we already have a mapping for this flow
    auto it = m_udp_map.find(key);
    if (it != m_udp_map.end() && it->second.vport != 0) {
        it->second.last_access = now;
        m_vport_to_udp[it->second.vport].last_access = now;
        return it->second.vport;
    }

    // 2. Allocate a new port from the free pool
    if (m_free_vports.empty()) {
        LOG_ERROR("[NAT] UDP Virtual Port Pool Exhausted!");
        return 0;
    }

    uint16_t vport = m_free_vports.front();
    m_free_vports.pop_front();

    // 3. Create bidirectional mapping
    m_udp_map[key] = { dest, now, key, vport };
    m_vport_to_udp[vport] = { key, now, true };

    return vport;
}

std::optional<UdpKey4> NatManager::get_udp_key_by_virtual_port(uint16_t vport) {
    std::shared_lock<std::shared_mutex> lock(m_global_mtx);
    auto it = m_vport_to_udp.find(vport);
    if (it != m_vport_to_udp.end()) {
        // Update access time (Note: requires unique lock for writing, or atomic)
        // For simplicity and performance, we'll skip the update in the shared_lock path
        // and rely on the receive path (allocate_udp_virtual_port) to keep it alive.
        return it->second.key;
    }
    return std::nullopt;
}

std::optional<OriginalDestination> NatManager::get_udp_mapping(const UdpKey4& key) {
    std::shared_lock<std::shared_mutex> lock(m_global_mtx);
    auto it = m_udp_map.find(key);
    if (it != m_udp_map.end()) {
        return it->second.dest;
    }
    return std::nullopt;
}

std::optional<OriginalDestination> NatManager::get_mapping(uint64_t key) {
    uint16_t port_nbo = (uint16_t)(key & 0xFFFF);
    uint16_t port_hbo = ntohs(port_nbo);
    
    // Fast path: Check if it's a known virtual port
    if (port_hbo >= VPORT_START && port_hbo <= VPORT_END) {
        auto key4 = get_udp_key_by_virtual_port(port_hbo);
        if (key4) {
            return get_udp_mapping(*key4);
        }
    }

    // Otherwise check TCP map
    std::shared_lock<std::shared_mutex> lock(m_global_mtx);
    auto it_tcp = m_tcp_map.find(key);
    if (it_tcp != m_tcp_map.end()) {
        return it_tcp->second.dest;
    }

    return std::nullopt;
}
