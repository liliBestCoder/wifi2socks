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
    IO_READ,    // Zero-byte read completed
    IO_WRITE,   // Write completed (reserved)
    IO_CONNECT  // ConnectEx completed
};

// Extended OVERLAPPED to hold context
struct IO_CONTEXT {
    OVERLAPPED overlapped;
    IO_TYPE type;
};

struct SocketContext {
    static const uint32_t MAGIC_VAL = 0xCAFEBABE;
    uint32_t magic;
    SOCKET sock;
    
    // Updated callback signature: data, len, addr (for UDP)
    std::function<void(char*, int, sockaddr_in*)> on_read;
    
    std::function<void()> on_write; // Used for Connect completion
    std::function<void()> on_close; 
    
    IO_CONTEXT read_io;    // Reuse for reads
    IO_CONTEXT connect_io; // Reuse for connects
    bool read_pending;     // Avoid double posting
    bool paused;           // Flow control
    
    // UDP Support
    bool is_udp;
    char buffer[4096];
    WSABUF wsaBuf;
    sockaddr_in remote_addr;
    int remote_addr_len;
    
    std::atomic<int> ref_count;         // Reference Counting for lifetime management

    SocketContext() {
        magic = MAGIC_VAL;
        memset(&read_io, 0, sizeof(read_io));
        read_io.type = IO_READ;
        memset(&connect_io, 0, sizeof(connect_io));
        connect_io.type = IO_CONNECT;
        read_pending = false;
        paused = false;
        sock = INVALID_SOCKET;
        ref_count = 0;
        
        is_udp = false;
        memset(buffer, 0, sizeof(buffer));
        wsaBuf.buf = buffer;
        wsaBuf.len = 4096;
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr_len = sizeof(remote_addr);
    }
    
    ~SocketContext() {
        magic = 0xDEADBEEF;
    }
};

class Worker {
public:
    Worker();
    ~Worker();
    
    void start();
    void stop();
    
    // Thread-safe methods to add/remove sockets.
    // Updated: on_read takes data args. is_udp flag added.
    void add_socket(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read, std::function<void()> on_write, std::function<void()> on_close, bool is_udp = false);
    void remove_socket(SOCKET s, std::function<void()> on_done = nullptr);
    
    // Flow Control
    void pause_read(SOCKET s);
    void resume_read(SOCKET s);

    // New: Async Connect for IOCP
    void connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect);

    // Run arbitrary task in worker thread
    void queue_task(std::function<void()> task);

private:
    void loop();
    void post_read(SocketContext* ctx);
    
    // Reference counting helpers
    void retain_context(SocketContext* ctx);
    void release_context(SocketContext* ctx);

    HANDLE m_iocp;
    std::thread m_thread;
    std::mutex m_mtx;
    std::map<SOCKET, SocketContext*> m_sockets; // Pointers to ensure address stability for IOCP
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