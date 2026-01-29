#include "worker.h"
#include <iostream>
#include <algorithm>
#include <chrono>

// Worker Implementation

Worker::Worker() : m_running(false) {}

Worker::~Worker() {
    stop();
}

void Worker::start() {
    if (m_running) return;
    m_running = true;
    m_thread = std::thread(&Worker::loop, this);
}

void Worker::stop() {
    if (!m_running) return;
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
}

void Worker::add_socket(SOCKET s, std::function<void()> on_read, std::function<void()> on_close) {
    std::lock_guard<std::mutex> lock(m_mtx);
    // Queue the addition to ensure thread safety inside the loop
    m_task_queue.push_back([this, s, on_read, on_close]() {
        SocketContext ctx;
        ctx.sock = s;
        ctx.on_read = on_read;
        ctx.on_close = on_close;
        m_sockets[s] = ctx;
    });
}

void Worker::remove_socket(SOCKET s) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s]() {
        m_sockets.erase(s);
    });
}

void Worker::queue_task(std::function<void()> task) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back(task);
}

void Worker::loop() {
    fd_set read_fds;
    struct timeval tv;
    std::vector<std::function<void()>> current_tasks;

    while (m_running) {
        // 1. Process Tasks
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            if (!m_task_queue.empty()) {
                current_tasks.swap(m_task_queue);
            }
        }
        
        for (auto& task : current_tasks) {
            task();
        }
        current_tasks.clear();

        // 2. Prepare Select
        FD_ZERO(&read_fds);
        SOCKET max_sock = 0;
        int sock_count = 0;

        // Note: m_sockets is only modified by tasks running in this thread now
        for (auto& pair : m_sockets) {
            if (sock_count >= FD_SETSIZE) break; 
            FD_SET(pair.first, &read_fds);
            if (pair.first > max_sock) max_sock = pair.first;
            sock_count++;
        }

        tv.tv_sec = 0;
        tv.tv_usec = 10000; // 10ms timeout

        // 3. Select
        if (sock_count > 0) {
            int activity = select(0, &read_fds, NULL, NULL, &tv);

            if (activity > 0) {
                // Collect readable sockets first to avoid iterator invalidation issues if callbacks modify the map
                // (Though callbacks shouldn't modify map directly, they might queue tasks)
                std::vector<SOCKET> readable;
                for (auto& pair : m_sockets) {
                    if (FD_ISSET(pair.first, &read_fds)) {
                        readable.push_back(pair.first);
                    }
                }

                for (SOCKET s : readable) {
                    // Check if still exists
                    auto it = m_sockets.find(s);
                    if (it != m_sockets.end()) {
                        if (it->second.on_read) it->second.on_read();
                    }
                }
            } else if (activity == SOCKET_ERROR) {
                // Handle error?
            }
        } else {
            // Sleep a bit if no sockets to avoid busy loop
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

// WorkerPool Implementation

WorkerPool& WorkerPool::instance() {
    static WorkerPool pool;
    return pool;
}

void WorkerPool::init(int count) {
    if (!m_workers.empty()) return;
    for (int i = 0; i < count; ++i) {
        Worker* w = new Worker();
        w->start();
        m_workers.push_back(w);
    }
    m_next_idx = 0;
}

Worker* WorkerPool::get_worker(uint32_t hash) {
    if (m_workers.empty()) return nullptr;
    return m_workers[hash % m_workers.size()];
}

Worker* WorkerPool::get_next_worker() {
    if (m_workers.empty()) return nullptr;
    return m_workers[m_next_idx++ % m_workers.size()];
}
