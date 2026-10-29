#ifndef CONNECTION_POOL_H
#define CONNECTION_POOL_H

#include <winsock2.h>
#include <string>
#include <unordered_map>
#include <list>
#include <mutex>
#include <chrono>
#include <memory>
#include <thread>

class ConnectionPool {
public:
    static ConnectionPool& instance();

    ConnectionPool(const ConnectionPool&) = delete;
    ConnectionPool& operator=(const ConnectionPool&) = delete;

    SOCKET acquire(const std::string& destination);
    void release(const std::string& destination, SOCKET socket);
    void cleanup();

private:
    ConnectionPool();
    ~ConnectionPool();

    using SocketEntry = std::pair<SOCKET, std::chrono::steady_clock::time_point>;
    using SocketList = std::list<SocketEntry>;

    std::unordered_map<std::string, SocketList> m_pool;
    std::mutex m_mutex;
    std::thread m_cleanup_thread;
    bool m_running;
};

#endif // CONNECTION_POOL_H
