#pragma once

#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif

#include <winsock2.h>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <functional>
#include <map>
#include <atomic>

struct SocketContext {
    SOCKET sock;
    std::function<void()> on_read;
    std::function<void()> on_close; 
};

class Worker {
public:
    Worker();
    ~Worker();
    
    void start();
    void stop();
    
    // Thread-safe methods to add/remove sockets
    void add_socket(SOCKET s, std::function<void()> on_read, std::function<void()> on_close);
    void remove_socket(SOCKET s);
    
    // Run arbitrary task in worker thread
    void queue_task(std::function<void()> task);

private:
    void loop();
    
    std::thread m_thread;
    std::mutex m_mtx;
    std::map<SOCKET, SocketContext> m_sockets;
    std::vector<std::function<void()>> m_task_queue; 
    std::atomic<bool> m_running;
};

class WorkerPool {
public:
    static WorkerPool& instance();
    void init(int count);
    Worker* get_worker(uint32_t hash);
    Worker* get_next_worker();

private:
    std::vector<Worker*> m_workers;
    std::atomic<size_t> m_next_idx;
};
