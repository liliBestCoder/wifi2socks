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
    std::vector<uint8_t> buf;
    sockaddr_in remote_addr;
    int remote_addr_len;
    SocketContext* parent;

    IO_CONTEXT() : type(IO_READ), sock(INVALID_SOCKET), remote_addr_len(0), parent(nullptr) {
        memset(&overlapped, 0, sizeof(OVERLAPPED));
    }
};

struct SocketContext {
    static const uint32_t MAGIC_VAL = 0xCAFEBABE;
    uint32_t magic;
    SOCKET sock;
    
    std::function<void(char*, int, sockaddr_in*)> on_read;
    std::function<void(int)> on_write; 
    std::function<void()> on_close; 
    std::function<void()> on_remove_done; 
    
    std::atomic<bool> read_pending;
    std::atomic<bool> closing;          
    bool is_udp;
    
    std::atomic<int> pending_io;        
    void* user_data;                    

    SocketContext() : magic(MAGIC_VAL), sock(INVALID_SOCKET), read_pending(false), 
                     closing(false), is_udp(false), pending_io(0), user_data(nullptr) {
    }
    
    ~SocketContext() {
        magic = 0xDEADBEEF;
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
    void add_socket(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read, std::function<void(int)> on_write, std::function<void()> on_close, bool is_udp = false);
    void remove_socket(SOCKET s, std::function<void()> on_done = nullptr);
    void connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect, 
                      std::function<void(char*, int, sockaddr_in*)> on_read = nullptr,
                      std::function<void(int)> on_write = nullptr,
                      std::function<void()> on_close = nullptr);
    bool send_async(SOCKET s, std::vector<uint8_t>&& data);
    bool send_async(SOCKET s, char* buf, int len);
    void read_async(SOCKET s);
    void update_read_callback(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read);
    void queue_task(std::function<void()> task);
    
    HANDLE get_shared_iocp() const { return m_shared_iocp; }
    SocketContext* find_context(SOCKET s);

    void for_each_worker(std::function<void(Worker*)> callback);

private:
    WorkerPool() : m_shared_iocp(NULL), m_next_idx(0) {}
    ~WorkerPool();

    HANDLE m_shared_iocp;
    std::vector<Worker*> m_workers;
    std::atomic<size_t> m_next_idx;

    std::unordered_map<SOCKET, SocketContext*> m_global_sockets;
    std::mutex m_global_mtx;

    // 内部方法
    void post_read(SocketContext* ctx);
    void post_write(SocketContext* ctx, std::vector<uint8_t>&& data);
    void register_context(SOCKET s, SocketContext* ctx);
    void unregister_context(SOCKET s);
};