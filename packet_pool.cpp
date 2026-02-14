#include "packet_pool.h"

PacketPool& PacketPool::instance() {
    static PacketPool pool;
    return pool;
}

void PacketPool::init(size_t size) {
    while (m_lock.test_and_set(std::memory_order_acquire));
    if (!m_storage.empty()) {
        m_lock.clear(std::memory_order_release);
        return;
    }

    m_storage.resize(size);
    m_pool.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        m_pool.push_back(&m_storage[i]);
    }
    m_lock.clear(std::memory_order_release);
}

RawPacket* PacketPool::acquire() {
    while (m_lock.test_and_set(std::memory_order_acquire));
    if (m_pool.empty()) {
        m_lock.clear(std::memory_order_release);
        return nullptr;
    }
    RawPacket* p = m_pool.back();
    m_pool.pop_back();
    m_lock.clear(std::memory_order_release);
    return p;
}

void PacketPool::release(RawPacket* p) {
    if (!p) return;
    while (m_lock.test_and_set(std::memory_order_acquire));
    m_pool.push_back(p);
    m_lock.clear(std::memory_order_release);
}