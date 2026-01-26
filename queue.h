// ===== include/queue.h =====
#ifndef QUEUE_H
#define QUEUE_H

#include <atomic>
#include <vector>

template<typename T>
struct RingQueue {
    std::vector<T> buf;
    size_t size;
    std::atomic<size_t> head{ 0 };
    std::atomic<size_t> tail{ 0 };

    RingQueue(size_t n) : buf(n), size(n) {}

    bool push(const T& v) {
        size_t t = tail.load(std::memory_order_relaxed);
        size_t next = (t + 1) % size;
        if (next == head.load(std::memory_order_acquire)) return false; // ¶ÓÁÐÂú
        buf[t] = v;
        tail.store(next, std::memory_order_release);
        return true;
    }

    bool pop(T& v) {
        size_t h = head.load(std::memory_order_relaxed);
        if (h == tail.load(std::memory_order_acquire)) return false; // ¶ÓÁÐ¿Õ
        v = buf[h];
        head.store((h + 1) % size, std::memory_order_release);
        return true;
    }
};

#endif