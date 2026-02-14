#include "nat_manager.h"
#include "logger.h"
#include "app_config.h"
#include <windows.h>

NatManager& NatManager::instance() {
    static NatManager inst;
    return inst;
}

NatManager::NatManager() {}
NatManager::~NatManager() {}

void NatManager::create_tcp_mapping(uint64_t key, const OriginalDestination& dest) {
    auto& shard = m_shards[key % NUM_SHARDS];
    std::unique_lock lock(shard.mtx);
    shard.tcp_map[key] = dest;
    uint32_t ip = static_cast<uint32_t>(key >> 16);
    uint16_t port = static_cast<uint16_t>(key & 0xFFFF);
    LOG_DEBUG("[NAT] Created TCP mapping: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
        ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, ntohs(port),
        dest.ip & 0xFF, (dest.ip >> 8) & 0xFF, (dest.ip >> 16) & 0xFF, (dest.ip >> 24) & 0xFF, ntohs(dest.port));
}

void NatManager::remove_tcp_mapping(uint64_t key) {
    auto& shard = m_shards[key % NUM_SHARDS];
    std::unique_lock lock(shard.mtx);
    shard.tcp_map.erase(key);
}

void NatManager::create_or_update_udp_mapping(uint64_t key, const OriginalDestination& dest) {
    auto& shard = m_shards[key % NUM_SHARDS];
    std::unique_lock lock(shard.mtx);
    shard.udp_map[key] = { dest, GetTickCount64() };
}

std::optional<OriginalDestination> NatManager::get_mapping(uint64_t key) {
    auto& shard = m_shards[key % NUM_SHARDS];
    std::shared_lock lock(shard.mtx);
    
    auto it_tcp = shard.tcp_map.find(key);
    if (it_tcp != shard.tcp_map.end()) {
        return it_tcp->second;
    }

    auto it_udp = shard.udp_map.find(key);
    if (it_udp != shard.udp_map.end()) {
        return it_udp->second.first;
    }

    return std::nullopt;
}
