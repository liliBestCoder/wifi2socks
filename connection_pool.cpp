#include "connection_pool.h"
#include "app_config.h"
#include "logger.h" // Assuming a logger is available
#include <vector>

const std::chrono::minutes IDLE_TIMEOUT(5);

ConnectionPool& ConnectionPool::instance() {
    static ConnectionPool pool;
    return pool;
}

ConnectionPool::ConnectionPool() : m_running(true) {
    m_cleanup_thread = std::thread([this]() {
        while (m_running) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
            cleanup();
        }
    });
}

ConnectionPool::~ConnectionPool() {
    m_running = false;
    if (m_cleanup_thread.joinable()) {
        m_cleanup_thread.join();
    }
    // Clean up all remaining sockets
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& pair : m_pool) {
        for (auto& entry : pair.second) {
            closesocket(entry.first);
        }
    }
    m_pool.clear();
}

SOCKET ConnectionPool::acquire(const std::string& destination) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_pool.find(destination);
    if (it != m_pool.end()) {
        auto& socket_list = it->second;
        while (!socket_list.empty()) {
            SocketEntry entry = socket_list.front();
            socket_list.pop_front();
            
            // Check if the connection is still valid using a non-blocking read
            char buf;
            int result = recv(entry.first, &buf, 1, MSG_PEEK);
            
            if (result == 0 || (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)) {
                // Connection is closed or has an error
                closesocket(entry.first);
                continue; // Try the next one
            }
            
            // Check if timed out
            if (std::chrono::steady_clock::now() - entry.second < IDLE_TIMEOUT) {
                LOG_DEBUG("[ConnPool] Reusing connection for %s", destination.c_str());
                return entry.first;
            } else {
                // Connection timed out
                closesocket(entry.first);
            }
        }
    }
    LOG_DEBUG("[ConnPool] No reusable connection for %s, creating new.", destination.c_str());
    return INVALID_SOCKET;
}

void ConnectionPool::release(const std::string& destination, SOCKET socket) {
    if (socket == INVALID_SOCKET) {
        return;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    LOG_DEBUG("[ConnPool] Releasing connection for %s to pool.", destination.c_str());
    m_pool[destination].push_back({socket, std::chrono::steady_clock::now()});
}

void ConnectionPool::cleanup() {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto now = std::chrono::steady_clock::now();
    int cleaned_count = 0;

    for (auto& pair : m_pool) {
        auto& socket_list = pair.second;
        socket_list.remove_if([&](const SocketEntry& entry) {
            if (now - entry.second > IDLE_TIMEOUT) {
                closesocket(entry.first);
                cleaned_count++;
                return true;
            }
            return false;
        });
    }
    if (cleaned_count > 0) {
        LOG_DEBUG("[ConnPool] Cleaned up %d stale connections.", cleaned_count);
    }
}
