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
    IO_WRITE,   // Async Write completed
    IO_CONNECT,  // ConnectEx completed
    IO_REMOVE
};

// Extended OVERLAPPED to hold context
struct IO_CONTEXT {
    OVERLAPPED overlapped;
    IO_TYPE type;
    SOCKET sock;
    std::function<void()> on_done;
    std::vector<uint8_t> buf;
};

struct SocketContext {
    static const uint32_t MAGIC_VAL = 0xCAFEBABE;
    uint32_t magic;
    SOCKET sock;
    
    // Callbacks
    std::function<void(char*, int, sockaddr_in*)> on_read;
    std::function<void(int)> on_write; 
    std::function<void()> on_close; 
    std::function<void()> on_remove_done; // Callback for when context is finally deleted
    
    IO_CONTEXT read_io;    
    IO_CONTEXT write_io;   
    IO_CONTEXT connect_io; 
    
    bool read_pending;     
    bool write_pending;    
    bool paused;           
    bool closing;          // Scheme A: Mark for deletion
    
    // UDP Support
    bool is_udp;
    char buffer[4096];
    WSABUF wsaBuf;
    WSABUF wsaWriteBuf;    
    sockaddr_in remote_addr;
    int remote_addr_len;

    std::queue<std::vector<uint8_t>> write_queue; // Added for multiple pending writes
    
    std::atomic<int> pending_io;        // Number of outstanding overlapped operations
    void* user_data;                    // User-defined context data

    SocketContext() : pending_io(0), closing(false), user_data(nullptr) {
        magic = MAGIC_VAL;
        
        memset(&read_io.overlapped, 0, sizeof(OVERLAPPED));
        read_io.type = IO_READ;
        read_io.sock = INVALID_SOCKET;
        
        memset(&write_io.overlapped, 0, sizeof(OVERLAPPED));
        write_io.type = IO_WRITE;
        write_io.sock = INVALID_SOCKET;
        
        memset(&connect_io.overlapped, 0, sizeof(OVERLAPPED));
        connect_io.type = IO_CONNECT;
        connect_io.sock = INVALID_SOCKET;

        read_pending = false;
        write_pending = false;
        paused = false;
        sock = INVALID_SOCKET;
        
        is_udp = false;
        memset(buffer, 0, sizeof(buffer));
        wsaBuf.buf = buffer;
        wsaBuf.len = sizeof(buffer);
        wsaWriteBuf.buf = NULL;
        wsaWriteBuf.len = 0;
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
    
    void start(int core_index);
    void stop();
    
    // Thread-safe methods
    // on_write signature changed to take int status/bytes
    void add_socket(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read, std::function<void(int)> on_write, std::function<void()> on_close, bool is_udp = false);
    void remove_socket(SOCKET s, std::function<void()> on_done = nullptr);
    
    void pause_read(SOCKET s);
    void resume_read(SOCKET s);

    void connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect);
    
    // NEW: Async Send using IOCP
    // Returns true if operation posted (or queued), false if socket not found/closed.
    // The callback on_write passed in add_socket will be called when done.
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
    
    void retain_context(SocketContext* ctx);
    void release_context(SocketContext* ctx);

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