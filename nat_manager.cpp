#include "nat_manager.h"
#include "logger.h"
#include "app_config.h"
#include <intrin.h> // For _InterlockedExchange64

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

    m_cleanup_running = true;
    m_cleanup_thread = std::thread(&NatManager::cleanup_loop, this);
}

NatManager::~NatManager() {
    m_cleanup_running = false;
    m_cleanup_cv.notify_all();
    if (m_cleanup_thread.joinable()) {
        m_cleanup_thread.join();
    }
}

void NatManager::cleanup_loop() {
    while (m_cleanup_running) {
        std::unique_lock<std::mutex> lock(m_cleanup_mtx);
        m_cleanup_cv.wait_for(lock, std::chrono::seconds(10), [this] { return !m_cleanup_running; });
        if (!m_cleanup_running) break;

        std::unique_lock<std::shared_mutex> global_lock(m_global_mtx);
        cleanup_expired(GetTickCount64());
    }
}

void NatManager::cleanup() {
    std::unique_lock<std::shared_mutex> lock(m_global_mtx);
    cleanup_expired(GetTickCount64());
}

void NatManager::cleanup_expired(uint64_t now) {
    m_last_cleanup_time = now;

    size_t cleaned_udp = 0;
    // Cleanup UDP & VPorts
    for (auto it = m_vport_to_udp.begin(); it != m_vport_to_udp.end(); ) {
        if (now - it->second.last_access > UDP_TIMEOUT_MS) {
            m_udp_map.erase(it->second.key);
            m_free_vports.push_back(it->first);
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
    uint64_t now = GetTickCount64();
    
    // Fast path: Check existence with shared lock
    {
        std::shared_lock<std::shared_mutex> lock(m_global_mtx);
        auto it = m_tcp_map.find(key);
        if (it != m_tcp_map.end()) {
            it->second.last_access.store(now, std::memory_order_relaxed);
            return;
        }
    }

    // Slow path: Create new entry with unique lock
    std::unique_lock<std::shared_mutex> lock(m_global_mtx);
    m_tcp_map[key] = MappingEntry(dest, now, {}, 0);
    m_tcp_map[key].dest.worker_id = worker_id;
}

void NatManager::remove_tcp_mapping(uint64_t key) {
    std::unique_lock<std::shared_mutex> lock(m_global_mtx);
    m_tcp_map.erase(key);
}

void NatManager::create_or_update_udp_mapping(const UdpKey4& key, const OriginalDestination& dest, uint32_t worker_id) {
    uint64_t now = GetTickCount64();
    
    // Fast path: Update existing with shared lock
    {
        std::shared_lock<std::shared_mutex> lock(m_global_mtx);
        auto it = m_udp_map.find(key);
        if (it != m_udp_map.end()) {
            it->second.last_access.store(now, std::memory_order_relaxed);
            if (it->second.vport != 0) {
                m_vport_to_udp[it->second.vport].last_access.store(now, std::memory_order_relaxed);
            }
            return;
        }
    }

    // Slow path: Create with unique lock
    std::unique_lock<std::shared_mutex> lock(m_global_mtx);
    MappingEntry entry(dest, now, key, 0);
    entry.dest.worker_id = worker_id;
    m_udp_map[key] = entry;
}

uint16_t NatManager::allocate_udp_virtual_port(const UdpKey4& key, const OriginalDestination& dest) {
    uint64_t now = GetTickCount64();
    
    // Fast path: Existing mapping
    {
        std::shared_lock<std::shared_mutex> lock(m_global_mtx);
        auto it = m_udp_map.find(key);
        if (it != m_udp_map.end() && it->second.vport != 0) {
            it->second.last_access.store(now, std::memory_order_relaxed);
            m_vport_to_udp[it->second.vport].last_access.store(now, std::memory_order_relaxed);
            return it->second.vport;
        }
    }

    std::unique_lock<std::shared_mutex> lock(m_global_mtx);
    
    // Re-check under unique lock to avoid race
    auto it = m_udp_map.find(key);
    if (it != m_udp_map.end() && it->second.vport != 0) {
        it->second.last_access.store(now, std::memory_order_relaxed);
        m_vport_to_udp[it->second.vport].last_access.store(now, std::memory_order_relaxed);
        return it->second.vport;
    }

    if (m_free_vports.empty()) {
        LOG_WARN("[NAT] UDP Virtual Port Pool Exhausted!");
        m_cleanup_cv.notify_all();
        return 0;
    }

    uint16_t vport = m_free_vports.front();
    m_free_vports.pop_front();

    m_udp_map[key] = MappingEntry(dest, now, key, vport);
    m_vport_to_udp[vport] = VPortEntry(key, now, true);

    return vport;
}


std::optional<UdpKey4> NatManager::get_udp_key_by_virtual_port(uint16_t vport) {
    std::shared_lock<std::shared_mutex> lock(m_global_mtx);
    auto it = m_vport_to_udp.find(vport);
    if (it != m_vport_to_udp.end()) {
        uint64_t now = GetTickCount64();
        // Atomic update timestamp without unique lock
        it->second.last_access.store(now, std::memory_order_relaxed);
        auto it_u = m_udp_map.find(it->second.key);
        if (it_u != m_udp_map.end()) {
            it_u->second.last_access.store(now, std::memory_order_relaxed);
        }
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
    std::shared_lock<std::shared_mutex> lock(m_global_mtx);
    uint64_t now = GetTickCount64();
    
    // 1. First check TCP map
    auto it_tcp = m_tcp_map.find(key);
    if (it_tcp != m_tcp_map.end()) {
        _InterlockedExchange64((volatile long long*)&it_tcp->second.last_access, now);
        return it_tcp->second.dest;
    }

    // 2. Check if it's a known virtual port (UDP return path)
    uint16_t port_nbo = (uint16_t)(key & 0xFFFF);
    uint16_t port_hbo = ntohs(port_nbo);
    
    if (port_hbo >= VPORT_START && port_hbo <= VPORT_END) {
        auto it_v = m_vport_to_udp.find(port_hbo);
        if (it_v != m_vport_to_udp.end()) {
            _InterlockedExchange64((volatile long long*)&it_v->second.last_access, now);
            auto it_u = m_udp_map.find(it_v->second.key);
            if (it_u != m_udp_map.end()) {
                _InterlockedExchange64((volatile long long*)&it_u->second.last_access, now);
                return it_u->second.dest;
            }
        }
    }

    return std::nullopt;
}
