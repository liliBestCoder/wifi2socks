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
    
    // Lazy cleanup logic
    if (now - shard.last_cleanup_time > 10000) { 
        std::unique_lock<std::shared_mutex> lock(shard.mtx);
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
        shard.last_cleanup_time = now;
        shard.tcp_map[key] = { d, now };
    } else {
        std::unique_lock<std::shared_mutex> lock(shard.mtx);
        shard.tcp_map[key] = { d, now };
    }
}

void NatManager::remove_tcp_mapping(uint64_t key) {
    auto& shard = m_shards[key % NUM_SHARDS];
    std::unique_lock<std::shared_mutex> lock(shard.mtx);
    shard.tcp_map.erase(key);
}

void NatManager::create_or_update_udp_mapping(const UdpKey4& key, const OriginalDestination& dest, uint32_t worker_id) {
    // Distribute shards based on source IP and port for consistency with TCP if needed, 
    // but here we use src_ip and src_port to pick shard.
    uint64_t shard_key = make_key(key.src_ip, key.src_port);
    auto& shard = m_shards[shard_key % NUM_SHARDS];
    std::unique_lock<std::shared_mutex> lock(shard.mtx);
    OriginalDestination d = dest;
    d.worker_id = worker_id;
    shard.udp_map[key] = { d, GetTickCount64() };
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

    // Fallback for UDP: if only 2-tuple key is provided, find the most recent mapping
    // for this source IP/Port. This helps the App layer (proxy) which only has 2-tuple info.
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
