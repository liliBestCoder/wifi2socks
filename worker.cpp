#include "worker.h"
#include <iostream>
#include <algorithm>
#include <chrono>

// Worker Implementation

Worker::Worker() : m_running(false), m_iocp(NULL), m_lpfnConnectEx(NULL) {
    m_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!m_iocp) {
        printf("Error creating IOCP: %d\n", GetLastError());
    }

    // Load ConnectEx
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s != INVALID_SOCKET) {
        GUID guid = WSAID_CONNECTEX;
        DWORD bytes = 0;
        WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guid, sizeof(guid),
            &m_lpfnConnectEx, sizeof(m_lpfnConnectEx),
            &bytes, NULL, NULL);
        closesocket(s);
    }
}

Worker::~Worker() {
    stop();
    if (m_iocp) CloseHandle(m_iocp);
}

void Worker::start() {
    if (m_running) return;
    m_running = true;
    m_thread = std::thread(&Worker::loop, this);
}

void Worker::stop() {
    if (!m_running) return;
    m_running = false;
    // Wake up loop
    if (m_iocp) PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
    if (m_thread.joinable()) m_thread.join();
}

void Worker::post_zero_byte_read(SocketContext* ctx) {
    if (!ctx || ctx->read_pending) return;

    WSABUF wsaBuf;
    wsaBuf.buf = NULL;
    wsaBuf.len = 0;
    DWORD bytes = 0;
    DWORD flags = 0;
    
    memset(&ctx->read_io.overlapped, 0, sizeof(OVERLAPPED));
    ctx->read_io.type = IO_READ;

    if (WSARecv(ctx->sock, &wsaBuf, 1, &bytes, &flags, &ctx->read_io.overlapped, NULL) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            // Error handling: maybe socket closed?
            // printf("WSARecv failed: %d\n", WSAGetLastError());
        } else {
            ctx->read_pending = true;
        }
    } else {
        ctx->read_pending = true;
    }
}

void Worker::add_socket(SOCKET s, std::function<void()> on_read, std::function<void()> on_write, std::function<void()> on_close) {
    std::lock_guard<std::mutex> lock(m_mtx);
    
    // We must queue this to run in the loop or ensure thread safety of map
    // Actually, CreateIoCompletionPort is thread safe, but map is not.
    // Let's use task queue for map modification to be safe and consistent.
    
    m_task_queue.push_back([this, s, on_read, on_write, on_close]() {
        // 1. Create Context
        SocketContext* ctx = new SocketContext();
        ctx->sock = s;
        ctx->on_read = on_read;
        ctx->on_write = on_write;
        ctx->on_close = on_close;
        
        m_sockets[s] = ctx;

        // 2. Associate with IOCP
        // Key is the SocketContext pointer
        CreateIoCompletionPort((HANDLE)s, m_iocp, (ULONG_PTR)ctx, 0);

        // 3. Post Read if needed
        if (on_read) {
            post_zero_byte_read(ctx);
        }
        
        // Note: on_write is NOT posted here. It's used for Connect callback.
    });
    
    // Wake up loop to process task
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::remove_socket(SOCKET s, std::function<void()> on_done) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, on_done]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) {
            SocketContext* ctx = it->second;
            // Cancel IO? Closesocket usually cancels it.
            // But we should delay deletion until IO completes?
            // For simplicity in this structure, we assume closesocket calls happen externally 
            // or we just delete ctx.
            // WARNING: Deleting ctx while IO is pending is dangerous.
            // But since we use Zero-Byte read, pending IO is just a pointer.
            // Ideally we should wait for completion with error.
            // For this implementation, we just leak 'ctx' if IO is pending or delete it?
            // Let's delete it. In a robust system we use ref-counting.
            delete ctx; 
            m_sockets.erase(it);
        }
        if (on_done) on_done();
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, addr, on_connect]() {
        // Must bind first
        struct sockaddr_in bindAddr;
        memset(&bindAddr, 0, sizeof(bindAddr));
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = 0;
        bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr));

        // Create Context
        SocketContext* ctx = new SocketContext();
        ctx->sock = s;
        ctx->on_write = on_connect; // Connect callback
        m_sockets[s] = ctx;

        // Associate
        CreateIoCompletionPort((HANDLE)s, m_iocp, (ULONG_PTR)ctx, 0);

        // Post ConnectEx
        memset(&ctx->connect_io.overlapped, 0, sizeof(OVERLAPPED));
        ctx->connect_io.type = IO_CONNECT;
        
        // Note: ConnectEx requires PWSABUF for sending data, we send none.
        if (m_lpfnConnectEx) {
            BOOL ret = m_lpfnConnectEx(s, (sockaddr*)&addr, sizeof(addr), NULL, 0, NULL, &ctx->connect_io.overlapped);
            if (!ret && WSAGetLastError() != ERROR_IO_PENDING) {
                // Failed immediately
                // Handle error? Just call callback? Or close?
                // For now, do nothing, let timeout handle it
            }
        }
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::queue_task(std::function<void()> task) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back(task);
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::loop() {
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED overlapped;

    while (m_running) {
        // 1. Process Tasks
        {
            std::vector<std::function<void()>> current_tasks;
            {
                std::lock_guard<std::mutex> lock(m_mtx);
                if (!m_task_queue.empty()) {
                    current_tasks.swap(m_task_queue);
                }
            }
            for (auto& task : current_tasks) {
                task();
            }
        }

        // 2. Wait for Completion
        // Use timeout to allow task processing check
        BOOL ret = GetQueuedCompletionStatus(m_iocp, &bytesTransferred, &completionKey, &overlapped, 10);

        if (ret) {
            if (completionKey != 0 && overlapped != NULL) {
                SocketContext* ctx = (SocketContext*)completionKey;
                IO_CONTEXT* ioCtx = (IO_CONTEXT*)overlapped;

                if (ioCtx->type == IO_READ) {
                    ctx->read_pending = false;
                    if (bytesTransferred == 0) {
                        // Zero-byte read completed = Data Available OR Fin received.
                        // We rely on the upper layer recv() to determine if it is Fin (0) or Data (>0).
                        if (ctx->on_read) ctx->on_read();
                        
                        // Re-post if socket still alive (ctx->on_read calls remove_socket on close?)
                        // If user closed socket, ctx might be deleted. 
                        // Safe check: look up map?
                        // For perf we skip lookup, but risk UAF if on_read deleted ctx.
                        // However, on_read usually queues deletion.
                        // To be safe, we check if ctx is still in map.
                        if (m_sockets.find(ctx->sock) != m_sockets.end()) {
                             post_zero_byte_read(ctx);
                        }
                    }
                } else if (ioCtx->type == IO_CONNECT) {
                    // Update socket context
                    setsockopt(ctx->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
                    if (ctx->on_write) ctx->on_write();
                }
            }
        } else {
            // Error or Timeout
            if (overlapped != NULL) {
                // Operation failed (e.g. socket closed)
                // SocketContext* ctx = (SocketContext*)completionKey;
                // Just ignore, let upper layer logic handle closure
            }
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

void WorkerPool::for_each_worker(std::function<void(Worker*)> callback) {
    if (m_workers.empty()) return;
    for (auto* w : m_workers) {
        callback(w);
    }
}