#include "nat_manager.h"
#include "logger.h"
#include "app_config.h"

// Implementation of NatManager

NatManager& NatManager::instance() {
    static NatManager inst;
    return inst;
}

NatManager::NatManager() {}
NatManager::~NatManager() {}

void NatManager::create_tcp_mapping(uint64_t key, const OriginalDestination& dest, uint32_t worker_id) {
    auto& shard = m_shards[key % NUM_SHARDS];
    
    uint64_t now = GetTickCount64();
    OriginalDestination d = dest;
    d.worker_id = worker_id;
    
    std::unique_lock<std::shared_mutex> lock(shard.mtx);
    
    // Lazy cleanup logic
    if (now - shard.last_cleanup_time > 10000) { 
        // Cleanup TCP
        for (auto it = shard.tcp_map.begin(); it != shard.tcp_map.end();) {
            if (now - it->second.last_access > TCP_TIMEOUT_MS) {
                it = shard.tcp_map.erase(it);
            } else {
                ++it;
            }
        }
        // Cleanup UDP
        for (auto it = shard.udp_map.begin(); it != shard.udp_map.end();) {
            if (now - it->second.last_access > UDP_TIMEOUT_MS) {
                it = shard.udp_map.erase(it);
            } else {
                ++it;
            }
        }
        // Cleanup VPort
        for (auto it = shard.vport_to_udp.begin(); it != shard.vport_to_udp.end();) {
            if (now - it->second.last_access > UDP_TIMEOUT_MS) {
                it = shard.vport_to_udp.erase(it);
            } else {
                ++it;
            }
        }
        shard.last_cleanup_time = now;
    }
    
    shard.tcp_map[key] = { d, now };
}

void NatManager::remove_tcp_mapping(uint64_t key) {
    auto& shard = m_shards[key % NUM_SHARDS];
    std::unique_lock<std::shared_mutex> lock(shard.mtx);
    shard.tcp_map.erase(key);
}

void NatManager::create_or_update_udp_mapping(const UdpKey4& key, const OriginalDestination& dest, uint32_t worker_id) {
    uint64_t shard_key = make_key(key.src_ip, key.src_port);
    auto& shard = m_shards[shard_key % NUM_SHARDS];
    std::unique_lock<std::shared_mutex> lock(shard.mtx);
    
    uint16_t vport = 0;
    auto it = shard.udp_map.find(key);
    if (it != shard.udp_map.end()) vport = it->second.vport;

    OriginalDestination d = dest;
    d.worker_id = worker_id;
    shard.udp_map[key] = { d, GetTickCount64(), key, vport };
}

uint16_t NatManager::allocate_udp_virtual_port(const UdpKey4& key, const OriginalDestination& dest) {
    uint64_t key64 = make_key(key.src_ip, key.src_port);
    auto& shard_k = m_shards[key64 % NUM_SHARDS];
    
    uint16_t existing_vport = 0;
    {
        std::shared_lock<std::shared_mutex> lock(shard_k.mtx);
        auto it = shard_k.udp_map.find(key);
        if (it != shard_k.udp_map.end() && it->second.vport != 0) {
            existing_vport = it->second.vport;
        }
    }

    uint64_t now = GetTickCount64();

    if (existing_vport != 0) {
        // Lazy update for vport_to_udp
        auto& shard_v = m_shards[existing_vport % NUM_SHARDS];
        {
            std::shared_lock<std::shared_mutex> lock_v(shard_v.mtx);
            auto it_v = shard_v.vport_to_udp.find(existing_vport);
            if (it_v != shard_v.vport_to_udp.end() && (now - it_v->second.last_access > 1000)) {
                lock_v.unlock();
                std::unique_lock<std::shared_mutex> ulock_v(shard_v.mtx);
                auto it_retry = shard_v.vport_to_udp.find(existing_vport);
                if (it_retry != shard_v.vport_to_udp.end()) {
                    it_retry->second.last_access = now;
                }
            }
        }
        
        // Lazy update for udp_map
        {
            std::shared_lock<std::shared_mutex> lock_k(shard_k.mtx);
            auto it_k = shard_k.udp_map.find(key);
            if (it_k != shard_k.udp_map.end() && (now - it_k->second.last_access > 1000)) {
                lock_k.unlock();
                std::unique_lock<std::shared_mutex> ulock_k(shard_k.mtx);
                auto it_retry = shard_k.udp_map.find(key);
                if (it_retry != shard_k.udp_map.end()) {
                    it_retry->second.last_access = now;
                }
            }
        }
        return existing_vport;
    }

    uint16_t vport = m_next_vport++;
    if (m_next_vport > VPORT_END) m_next_vport = VPORT_START;

    {
        std::unique_lock<std::shared_mutex> lock_k(shard_k.mtx);
        shard_k.udp_map[key] = { dest, now, key, vport };
    }
    
    auto& shard_v = m_shards[vport % NUM_SHARDS];
    {
        std::unique_lock<std::shared_mutex> lock_v(shard_v.mtx);
        shard_v.vport_to_udp[vport] = { key, now };
    }
    
    return vport;
}

std::optional<UdpKey4> NatManager::get_udp_key_by_virtual_port(uint16_t vport) {
    auto& shard_v = m_shards[vport % NUM_SHARDS]; 
    std::shared_lock<std::shared_mutex> lock(shard_v.mtx);
    auto it = shard_v.vport_to_udp.find(vport);
    if (it != shard_v.vport_to_udp.end()) {
        uint64_t now = GetTickCount64();
        if (now - it->second.last_access > 1000) {
            lock.unlock();
            std::unique_lock<std::shared_mutex> ulock(shard_v.mtx);
            auto it_retry = shard_v.vport_to_udp.find(vport);
            if (it_retry != shard_v.vport_to_udp.end()) {
                it_retry->second.last_access = now;
                return it_retry->second.key;
            }
            return std::nullopt;
        }
        return it->second.key;
    }
    return std::nullopt;
}

std::optional<OriginalDestination> NatManager::get_udp_mapping(const UdpKey4& key) {
    uint64_t shard_key = make_key(key.src_ip, key.src_port);
    auto& shard = m_shards[shard_key % NUM_SHARDS];
    std::shared_lock<std::shared_mutex> lock(shard.mtx);
    
    auto it = shard.udp_map.find(key);
    if (it != shard.udp_map.end()) {
        uint64_t now = GetTickCount64();
        if (now - it->second.last_access > 1000) {
            lock.unlock();
            std::unique_lock<std::shared_mutex> ulock(shard.mtx);
            auto it_retry = shard.udp_map.find(key);
            if (it_retry != shard.udp_map.end()) {
                it_retry->second.last_access = now;
                return it_retry->second.dest;
            }
            return std::nullopt;
        }
        return it->second.dest;
    }
    return std::nullopt;
}

std::optional<OriginalDestination> NatManager::get_mapping(uint64_t key) {
    uint16_t port_nbo = (uint16_t)(key & 0xFFFF);
    uint16_t port_hbo = ntohs(port_nbo);
    
    if (port_hbo >= VPORT_START && port_hbo <= VPORT_END) {
        auto key4 = get_udp_key_by_virtual_port(port_hbo);
        if (key4) {
            return get_udp_mapping(*key4);
        }
    }

    auto& shard = m_shards[key % NUM_SHARDS];
    std::shared_lock<std::shared_mutex> lock(shard.mtx); 
    
    uint64_t now = GetTickCount64();

    auto it_tcp = shard.tcp_map.find(key);
    if (it_tcp != shard.tcp_map.end()) {
        if (now - it_tcp->second.last_access > 1000) {
            lock.unlock();
            std::unique_lock<std::shared_mutex> ulock(shard.mtx);
            auto it_retry = shard.tcp_map.find(key);
            if (it_retry != shard.tcp_map.end()) {
                it_retry->second.last_access = now;
                return it_retry->second.dest;
            }
            return std::nullopt;
        }
        return it_tcp->second.dest;
    }

    std::optional<OriginalDestination> latest_udp;
    uint64_t max_access = 0;
    
    for (auto const& [udp_key, entry] : shard.udp_map) {
        if (make_key(udp_key.src_ip, udp_key.src_port) == key) {
            if (entry.last_access > max_access) {
                max_access = entry.last_access;
                latest_udp = entry.dest;
            }
        }
    }
    
    if (latest_udp) {
        return latest_udp;
    }

    return std::nullopt;
}
