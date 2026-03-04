#include "packet_pool.h"

PacketPool& PacketPool::instance() {
    static PacketPool pool;
    return pool;
}

void PacketPool::init(size_t size) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_storage.empty()) {
        return;
    }

    m_storage.resize(size);
    m_pool.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        m_pool.push_back(&m_storage[i]);
    }
}

RawPacket* PacketPool::acquire() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pool.empty()) {
        return nullptr;
    }
    RawPacket* p = m_pool.back();
    m_pool.pop_back();
    return p;
}

size_t PacketPool::acquire_batch(RawPacket** p, size_t count) {
    if (!p || count == 0) return 0;
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t actual = (std::min)(count, m_pool.size());
    for (size_t i = 0; i < actual; ++i) {
        p[i] = m_pool.back();
        m_pool.pop_back();
    }
    return actual;
}

void PacketPool::release(RawPacket* p) {
    if (!p) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pool.push_back(p);
}

void PacketPool::release_batch(RawPacket** p, size_t count) {
    if (!p || count == 0) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (size_t i = 0; i < count; ++i) {
        if (p[i]) m_pool.push_back(p[i]);
    }
}
