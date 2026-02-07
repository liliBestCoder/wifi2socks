#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include "nat_table.h"
#include <cstring>
#include <fstream>
#include <algorithm>
#include <vector>
#include <cctype>

NatTable& NatTable::instance() {
    static NatTable instance;
    return instance;
}

void NatTable::set(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, const WINDIVERT_ADDRESS* addr) {
    std::lock_guard<std::mutex> lock(m_mtx);
    NatEntry entry;
    entry.original_dst_ip = dst_ip;
    entry.original_dst_port = dst_port;
    entry.src_ip = src_ip;
    entry.src_port = src_port;
    if (addr) {
        entry.addr = *addr;
    } else {
        memset(&entry.addr, 0, sizeof(entry.addr));
    }
    entry.last_active = GetTickCount64();
    m_table[{src_ip, src_port}] = entry;
}

NatEntry NatTable::get(uint32_t src_ip, uint16_t src_port) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_table.find({src_ip, src_port});
    if (it != m_table.end()) {
        it->second.last_active = GetTickCount64();
        return it->second;
    }
    NatEntry empty{};
    return empty;
}

NatEntry NatTable::get_by_port(uint16_t local_src_port) {
    std::lock_guard<std::mutex> lock(m_mtx);
    for (auto& pair : m_table) {
        if (pair.first.second == local_src_port) {
            pair.second.last_active = GetTickCount64();
            return pair.second;
        }
    }
    NatEntry empty{};
    return empty;
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