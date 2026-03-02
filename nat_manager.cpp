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

void NatManager::cleanup_shard(Shard& shard, uint64_t now) {
    if (now - shard.last_cleanup_time < 10000) return;

    // Cleanup TCP
    for (auto it = shard.tcp_map.begin(); it != shard.tcp_map.end();) {
        if (now - it->second.last_access > TCP_TIMEOUT_MS) {
            it = shard.tcp_map.erase(it);
        }
        else {
            ++it;
        }
    }
    // Cleanup UDP
    for (auto it = shard.udp_map.begin(); it != shard.udp_map.end();) {
        if (now - it->second.last_access > UDP_TIMEOUT_MS) {
            it = shard.udp_map.erase(it);
        }
        else {
            ++it;
        }
    }
    // Cleanup VPort
    for (auto it = shard.vport_to_udp.begin(); it != shard.vport_to_udp.end();) {
        if (now - it->second.last_access > UDP_TIMEOUT_MS) {
            it = shard.vport_to_udp.erase(it);
        }
        else {
            ++it;
        }
    }
    shard.last_cleanup_time = now;
}

void NatManager::create_tcp_mapping(uint64_t key, const OriginalDestination& dest, uint32_t worker_id) {
    auto& shard = m_shards[key % NUM_SHARDS];
    
    uint64_t now = GetTickCount64();
    OriginalDestination d = dest;
    d.worker_id = worker_id;
    
    std::unique_lock<std::shared_mutex> lock(shard.mtx);
    cleanup_shard(shard, now);
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
    uint64_t now = GetTickCount64();

    std::unique_lock<std::shared_mutex> lock(shard.mtx);
    cleanup_shard(shard, now);
    
    uint16_t vport = 0;
    auto it = shard.udp_map.find(key);
    if (it != shard.udp_map.end()) vport = it->second.vport;

    OriginalDestination d = dest;
    d.worker_id = worker_id;
    shard.udp_map[key] = { d, now, key, vport };
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
        auto& shard_v = m_shards[existing_vport % NUM_SHARDS];
        // Use a faster update strategy for existing ports
        {
            std::unique_lock<std::shared_mutex> ulock_v(shard_v.mtx);
            auto it_v = shard_v.vport_to_udp.find(existing_vport);
            if (it_v != shard_v.vport_to_udp.end()) {
                it_v->second.last_access = now;
            }
        }
        {
            std::unique_lock<std::shared_mutex> ulock_k(shard_k.mtx);
            auto it_k = shard_k.udp_map.find(key);
            if (it_k != shard_k.udp_map.end()) {
                it_k->second.last_access = now;
            }
        }
        return existing_vport;
    }

    // Allocation logic: Limit search to prevent CPU spikes if pool is congested
    uint16_t start_vport = m_next_vport.load();
    uint16_t candidate = start_vport;
    uint16_t found_vport = 0;
    int max_tries = (std::min)((int)(VPORT_END - VPORT_START + 1), 4096); // Limit search

    for (int i = 0; i < max_tries; ++i) {
        uint16_t vport = candidate++;
        if (candidate > VPORT_END) candidate = VPORT_START;

        auto& shard_v = m_shards[vport % NUM_SHARDS];
        
        // Try shared lock first to see if it's free
        {
            std::shared_lock<std::shared_mutex> lock_v(shard_v.mtx);
            auto it_v = shard_v.vport_to_udp.find(vport);
            if (it_v == shard_v.vport_to_udp.end() || (now - it_v->second.last_access > UDP_TIMEOUT_MS)) {
                // Potential candidate found, upgrade to unique_lock
                lock_v.unlock();
                std::unique_lock<std::shared_mutex> ulock_v(shard_v.mtx);
                
                // Re-verify after locking
                auto it_retry = shard_v.vport_to_udp.find(vport);
                if (it_retry == shard_v.vport_to_udp.end() || (now - it_retry->second.last_access > UDP_TIMEOUT_MS)) {
                    shard_v.vport_to_udp[vport] = { key, now };
                    found_vport = vport;
                    m_next_vport.store(candidate);
                    break;
                }
                // If failed re-verify, the loop continues...
            }
        }
    }

    if (found_vport != 0) {
        std::unique_lock<std::shared_mutex> lock_k(shard_k.mtx);
        cleanup_shard(shard_k, now); // Only cleanup the target shard once
        shard_k.udp_map[key] = { dest, now, key, found_vport };
        return found_vport;
    }

    LOG_ERROR("[NAT] UDP Virtual Port Pool Exhausted!");
    return 0;
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
