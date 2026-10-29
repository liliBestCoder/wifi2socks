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

// Thread-local cache configuration
static const size_t TLS_CACHE_MAX = 1024;
thread_local RawPacket* t_cache[TLS_CACHE_MAX];
thread_local size_t t_count = 0;

RawPacket* PacketPool::acquire() {
    // 1. Try thread-local cache first (No Lock)
    if (t_count > 0) {
        return t_cache[--t_count];
    }

    // 2. Cache empty, refill from global pool (With Lock)
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pool.empty()) return nullptr;

    // Refill half of TLS cache to balance lock frequency and global availability
    size_t refill = (std::min)(m_pool.size(), TLS_CACHE_MAX / 2);
    for (size_t i = 0; i < refill; ++i) {
        t_cache[t_count++] = m_pool.back();
        m_pool.pop_back();
    }

    return t_cache[--t_count];
}

size_t PacketPool::acquire_batch(RawPacket** p, size_t count) {
    if (!p || count == 0) return 0;
    size_t got = 0;

    // 1. Take from TLS first
    while (got < count && t_count > 0) {
        p[got++] = t_cache[--t_count];
    }

    // 2. If still needed, take from global pool
    if (got < count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t remaining = count - got;
        size_t from_global = (std::min)(remaining, m_pool.size());
        for (size_t i = 0; i < from_global; ++i) {
            p[got++] = m_pool.back();
            m_pool.pop_back();
        }
    }

    return got;
}

void PacketPool::release(RawPacket* p) {
    if (!p) return;

    // 1. Try to put into thread-local cache (No Lock)
    if (t_count < TLS_CACHE_MAX) {
        t_cache[t_count++] = p;
        return;
    }

    // 2. Local cache full, flush half to global pool (With Lock)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t flush_count = TLS_CACHE_MAX / 2;
        for (size_t i = 0; i < flush_count; ++i) {
            m_pool.push_back(t_cache[--t_count]);
        }
    }

    // Now there is space in local cache
    t_cache[t_count++] = p;
}

void PacketPool::release_batch(RawPacket** p, size_t count) {
    if (!p || count == 0) return;

    size_t i = 0;
    // 1. Try to fill thread-local cache first
    while (i < count && t_count < TLS_CACHE_MAX) {
        if (p[i]) t_cache[t_count++] = p[i];
        i++;
    }

    // 2. Put remaining directly into global pool
    if (i < count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (; i < count; ++i) {
            if (p[i]) m_pool.push_back(p[i]);
        }
    }
}
