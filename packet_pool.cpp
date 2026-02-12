#include "packet_pool.h"

PacketPool& PacketPool::instance() {
    static PacketPool pool;
    return pool;
}

void PacketPool::init(size_t size) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_storage.empty()) return;

    m_storage.resize(size);
    m_pool.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        m_pool.push_back(&m_storage[i]);
    }
}

RawPacket* PacketPool::acquire() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pool.empty()) return nullptr;
    RawPacket* p = m_pool.back();
    m_pool.pop_back();
    return p;
}

void PacketPool::release(RawPacket* p) {
    if (!p) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pool.push_back(p);
}
