#include "nat_table.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <algorithm>
#include <vector>
#include <cctype>

NatTable& NatTable::instance() {
    static NatTable instance;
    return instance;
}

void NatTable::set(uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    std::lock_guard<std::mutex> lock(m_mtx);
    NatEntry entry;
    entry.original_dst_ip = dst_ip;
    entry.original_dst_port = dst_port;
    entry.last_active = GetTickCount64();
    m_table[src_port] = entry;
}

NatEntry NatTable::get(uint16_t src_port) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_table.find(src_port);
    if (it != m_table.end()) {
        it->second.last_active = GetTickCount64();
        return it->second;
    }
    return {0, 0, 0};
}

void NatTable::cleanup(uint64_t timeout_ms) {
    std::lock_guard<std::mutex> lock(m_mtx);
    uint64_t now = GetTickCount64();
    for (auto it = m_table.begin(); it != m_table.end(); ) {
        if (now - it->second.last_active > timeout_ms) {
            it = m_table.erase(it);
        } else {
            ++it;
        }
    }
}


