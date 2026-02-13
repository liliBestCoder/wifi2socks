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

void NatManager::create_tcp_mapping(const ClientKey& key, const OriginalDestination& dest) {
    std::unique_lock lock(m_tcp_mtx);
    m_tcp_map[key] = dest;
    LOG_DEBUG("[NAT] Created TCP mapping: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
        key.ip & 0xFF, (key.ip >> 8) & 0xFF, (key.ip >> 16) & 0xFF, (key.ip >> 24) & 0xFF, ntohs(key.port),
        dest.ip & 0xFF, (dest.ip >> 8) & 0xFF, (dest.ip >> 16) & 0xFF, (dest.ip >> 24) & 0xFF, ntohs(dest.port));
}

void NatManager::remove_tcp_mapping(const ClientKey& key) {
    std::unique_lock lock(m_tcp_mtx);
    m_tcp_map.erase(key);
}

void NatManager::create_or_update_udp_mapping(const ClientKey& key, const OriginalDestination& dest) {
    std::unique_lock lock(m_udp_mtx);
    m_udp_map[key] = { dest, GetTickCount64() };
}

std::optional<OriginalDestination> NatManager::get_mapping(const ClientKey& key) {
    // Try TCP first
    {
        std::shared_lock lock(m_tcp_mtx);
        auto it = m_tcp_map.find(key);
        if (it != m_tcp_map.end()) {
            return it->second;
        }
    }

    // Then try UDP
    {
        std::shared_lock lock(m_udp_mtx);
        auto it = m_udp_map.find(key);
        if (it != m_udp_map.end()) {
            // Update activity timestamp
            // Note: Since we have a shared_lock, we'd need a unique_lock to update.
            // For simplicity in this lookup, we skip the update or use a separate atomic if needed.
            return it->second.first;
        }
    }

    return std::nullopt;
}
