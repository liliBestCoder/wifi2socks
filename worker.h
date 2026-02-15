#pragma once

#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif

#include <winsock2.h>
#include <mswsock.h>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <functional>
#include <unordered_map>
#include <atomic>

constexpr int CONCURRENT_READ_COUNT = 4;

// IOCP Operation Types
enum IO_TYPE {
    IO_READ,    
    IO_WRITE,   
    IO_CONNECT, 
    IO_REMOVE,
    IO_TASK     // 通过 IOCP 投递的控制任务
};

struct SocketContext;

// 动态分配的 IO 上下文，对应一次异步操作
struct IO_CONTEXT {
    OVERLAPPED overlapped;
    IO_TYPE type;
    SOCKET sock;
    std::function<void()> task; 
    uint8_t buf[131072]; // 128KB fixed buffer to avoid vector allocations/zeroing
    size_t data_len;
    sockaddr_in remote_addr;
    int remote_addr_len;
    std::shared_ptr<SocketContext> parent;
    std::shared_ptr<std::vector<char>> write_buffer_ptr;

    IO_CONTEXT() : type(IO_READ), sock(INVALID_SOCKET), data_len(0), remote_addr_len(0), parent(nullptr) {
        memset(&overlapped, 0, sizeof(OVERLAPPED));
    }
};

struct SocketContext {
    SOCKET sock;
    
    std::function<void(char*, int, sockaddr_in*)> on_read;
    std::function<void(int)> on_write; 
    std::function<void()> on_remove_done; 
    
    std::atomic<bool> closing;          
    bool is_udp;
    
    void* user_data;                    

    SocketContext() : sock(INVALID_SOCKET), 
                     closing(false), is_udp(false), user_data(nullptr) {
    }
    
    ~SocketContext() {
    }
};

class Worker {
public:
    Worker(HANDLE iocp);
    ~Worker();
    
    void start(int core_index);
    void stop();
    
private:
    void loop();
    HANDLE m_iocp;
    std::thread m_thread;
    std::atomic<bool> m_running;
};

class WorkerPool {
    friend class Worker;
public:
    static WorkerPool& instance();
    void init(int count);
    
    // 全局控制方法，现在它们会将任务投递给共享 IOCP
    void add_socket(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read, std::function<void(int)> on_write, bool is_udp = false);
    void remove_socket(SOCKET s, std::function<void()> on_done = nullptr);
    void connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect, 
                      std::function<void(char*, int, sockaddr_in*)> on_read = nullptr,
                      std::function<void(int)> on_write = nullptr);
    bool send_async(SOCKET s, const uint8_t* data, size_t len);
    bool send_async(SOCKET s, char* buf, int len);
    bool send_async(SOCKET s, std::shared_ptr<std::vector<char>> buffer);
    void read_async(SOCKET s);
    void update_read_callback(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read);
    void queue_task(std::function<void()> task);
    
    HANDLE get_shared_iocp() const { return m_shared_iocp; }
    std::shared_ptr<SocketContext> find_context(SOCKET s);

    void for_each_worker(std::function<void(Worker*)> callback);

private:
    WorkerPool() : m_shared_iocp(NULL), m_next_idx(0) {}
    ~WorkerPool();

    HANDLE m_shared_iocp;
    std::vector<Worker*> m_workers;
    std::atomic<size_t> m_next_idx;

    struct Shard {
        std::unordered_map<SOCKET, std::shared_ptr<SocketContext>> sockets;
        std::mutex mtx;
    };
    static const size_t NUM_SHARDS = 32;
    Shard m_shards[NUM_SHARDS];

    // 内部方法
    void post_read(const std::shared_ptr<SocketContext>& ctx);
    void post_write(const std::shared_ptr<SocketContext>& ctx, const uint8_t* data, size_t len);
    void post_write(const std::shared_ptr<SocketContext>& ctx, std::shared_ptr<std::vector<char>> buffer);
    void register_context(SOCKET s, std::shared_ptr<SocketContext> ctx);
    void unregister_context(SOCKET s);
};