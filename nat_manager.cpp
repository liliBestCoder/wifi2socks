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

void NatManager::create_tcp_mapping(uint64_t key, const OriginalDestination& dest) {
    auto& shard = m_shards[key % NUM_SHARDS];
    
    uint64_t now = GetTickCount64();
    
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
        shard.tcp_map[key] = { dest, now };
    } else {
        std::unique_lock<std::shared_mutex> lock(shard.mtx);
        shard.tcp_map[key] = { dest, now };
    }
}

void NatManager::remove_tcp_mapping(uint64_t key) {
    auto& shard = m_shards[key % NUM_SHARDS];
    std::unique_lock<std::shared_mutex> lock(shard.mtx);
    shard.tcp_map.erase(key);
}

void NatManager::create_or_update_udp_mapping(uint64_t key, const OriginalDestination& dest) {
    auto& shard = m_shards[key % NUM_SHARDS];
    std::unique_lock<std::shared_mutex> lock(shard.mtx);
    shard.udp_map[key] = { dest, GetTickCount64() };
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
            auto it_retry = shard.udp_map.find(key);
            if (it_retry != shard.udp_map.end()) {
                it_retry->second.last_access = now;
                return it_retry->second.dest;
            }
            return std::nullopt;
        }
        return it_tcp->second.dest;
    }

    auto it_udp = shard.udp_map.find(key);
    if (it_udp != shard.udp_map.end()) {
        if (now - it_udp->second.last_access > 1000) {
            lock.unlock();
            std::unique_lock<std::shared_mutex> ulock(shard.mtx);
            auto it_retry = shard.udp_map.find(key);
            if (it_retry != shard.udp_map.end()) {
                it_retry->second.last_access = now;
                return it_retry->second.dest;
            }
            return std::nullopt;
        }
        return it_udp->second.dest;
    }

    return std::nullopt;
}
