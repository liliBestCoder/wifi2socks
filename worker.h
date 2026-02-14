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
#include <map>
#include <atomic>

// IOCP Operation Types
enum IO_TYPE {
    IO_READ,    
    IO_WRITE,   
    IO_CONNECT, 
    IO_REMOVE
};

struct SocketContext;

// Extended OVERLAPPED to hold context for a SINGLE asynchronous operation
struct IO_CONTEXT {
    OVERLAPPED overlapped;
    IO_TYPE type;
    SOCKET sock;
    std::function<void()> on_done;
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
    
    // Callbacks
    std::function<void(char*, int, sockaddr_in*)> on_read;
    std::function<void(int)> on_write; 
    std::function<void()> on_close; 
    std::function<void()> on_remove_done; 
    
    std::atomic<bool> read_pending;
    bool paused;           
    bool closing;          
    
    bool is_udp;
    
    std::atomic<int> pending_io;        // Number of outstanding overlapped operations
    void* user_data;                    // User-defined context data

    SocketContext() : magic(MAGIC_VAL), sock(INVALID_SOCKET), read_pending(false), 
                     paused(false), closing(false), is_udp(false), pending_io(0), user_data(nullptr) {
    }
    
    ~SocketContext() {
        magic = 0xDEADBEEF;
    }
};

class Worker {
public:
    Worker();
    ~Worker();
    
    void start(int core_index);
    void stop();
    
    void add_socket(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read, std::function<void(int)> on_write, std::function<void()> on_close, bool is_udp = false);
    void remove_socket(SOCKET s, std::function<void()> on_done = nullptr);
    
    void pause_read(SOCKET s);
    void resume_read(SOCKET s);

    void connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect);
    
    bool send_async(SOCKET s, char* buf, int len);
    bool send_async(SOCKET s, std::vector<uint8_t>&& data);
    void read_async(SOCKET s);
    void update_read_callback(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read);

    void queue_task(std::function<void()> task);
    void set_socket_user_data(SOCKET s, void* user_data);

private:
    void loop();
    void post_read(SocketContext* ctx);
    void post_write(SocketContext* ctx, std::vector<uint8_t>&& data);
    
    HANDLE m_iocp;
    std::thread m_thread;
    std::mutex m_mtx;
    std::map<SOCKET, SocketContext*> m_sockets; 
    std::vector<std::function<void()>> m_task_queue; 
    std::atomic<bool> m_running;
    
    LPFN_CONNECTEX m_lpfnConnectEx;
};

class WorkerPool {
public:
    static WorkerPool& instance();
    void init(int count);
    Worker* get_worker(uint32_t hash);
    Worker* get_next_worker();
    
    void for_each_worker(std::function<void(Worker*)> callback);

private:
    std::vector<Worker*> m_workers;
    std::atomic<size_t> m_next_idx;
};
