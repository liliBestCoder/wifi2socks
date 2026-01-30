#include "nat_table.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h> // for GetTickCount64

NatTable& NatTable::instance() {
    static NatTable instance;
    return instance;
}

void NatTable::set(uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    std::lock_guard<std::mutex> lk(m_mtx);
    NatEntry& e = m_table[src_port];
    e.original_dst_ip = dst_ip;
    e.original_dst_port = dst_port;
    e.last_active = GetTickCount64();
}

NatEntry NatTable::get(uint16_t src_port) {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_table.find(src_port);
    if (it != m_table.end()) return it->second;
    return {0, 0, 0};
}

void NatTable::cleanup(uint64_t timeout_ms) {
    std::lock_guard<std::mutex> lk(m_mtx);
    uint64_t now = GetTickCount64();
    
    for (auto it = m_table.begin(); it != m_table.end(); ) {
        if (now - it->second.last_active > timeout_ms) {
            it = m_table.erase(it);
        } else {
            ++it;
        }
    }
}
