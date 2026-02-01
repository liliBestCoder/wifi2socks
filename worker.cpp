#include "worker.h"
#include <iostream>
#include <algorithm>
#include <chrono>
#include <exception>

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
    SetThreadPriority(m_thread.native_handle(), THREAD_PRIORITY_ABOVE_NORMAL);
}

void Worker::stop() {
    if (!m_running) return;
    m_running = false;
    // Wake up loop
    if (m_iocp) PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
    if (m_thread.joinable()) m_thread.join();
}

// --- Reference Counting ---
void Worker::retain_context(SocketContext* ctx) {
    if (ctx) ctx->ref_count++;
}

void Worker::release_context(SocketContext* ctx) {
    if (ctx) {
        ctx->ref_count--;
        if (ctx->ref_count <= 0) {
            ctx->magic = 0xDEADBEEF;
            delete ctx;
        }
    }
}

void Worker::post_zero_byte_read(SocketContext* ctx) {
    if (!ctx || ctx->read_pending) return;

    static char dummy_buf[1];
    static WSABUF wsaBuf = { 0, dummy_buf };
    
    DWORD bytes = 0;
    DWORD flags = 0;
    
    memset(&ctx->read_io.overlapped, 0, sizeof(OVERLAPPED));
    ctx->read_io.type = IO_READ;

    // RETAIN for IO
    retain_context(ctx);

    if (WSARecv(ctx->sock, &wsaBuf, 1, &bytes, &flags, &ctx->read_io.overlapped, NULL) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            // Immediate failure
            release_context(ctx);
        } else {
            ctx->read_pending = true;
        }
    } else {
        // Immediate success (still generates completion)
        ctx->read_pending = true;
    }
}

void Worker::add_socket(SOCKET s, std::function<void()> on_read, std::function<void()> on_write, std::function<void()> on_close) {
    std::lock_guard<std::mutex> lock(m_mtx);
    
    m_task_queue.push_back([this, s, on_read, on_write, on_close]() {
        SocketContext* ctx = nullptr;
        
        auto it = m_sockets.find(s);
        bool new_association = false;
        
        if (it != m_sockets.end()) {
            ctx = it->second;
        } else {
            ctx = new SocketContext();
            ctx->sock = s;
            // RETAIN for Map ownership
            retain_context(ctx);
            m_sockets[s] = ctx;
            new_association = true;
        }
        
        ctx->on_read = on_read;
        ctx->on_write = on_write; 
        ctx->on_close = on_close;

        if (new_association) {
            CreateIoCompletionPort((HANDLE)s, m_iocp, (ULONG_PTR)ctx, 0);
        }

        if (on_read && !ctx->read_pending) {
            post_zero_byte_read(ctx);
        }
    });
    
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::remove_socket(SOCKET s, std::function<void()> on_done) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, on_done]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) {
            SocketContext* ctx = it->second;
            
            // CRITICAL FIX: Nullify callbacks immediately.
            // Even if IO is pending and ctx stays alive due to ref_count,
            // we must NOT call the callbacks because the owner (TcpCtx) is about to be deleted via on_done.
            ctx->on_read = nullptr;
            ctx->on_write = nullptr;
            ctx->on_close = nullptr;

            m_sockets.erase(it);
            // RELEASE for Map ownership
            release_context(ctx); 
        }
        if (on_done) on_done();
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, addr, on_connect]() {
        // Set TCP_NODELAY for low latency
        int flag = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

        // Bind required for ConnectEx
        struct sockaddr_in bindAddr;
        memset(&bindAddr, 0, sizeof(bindAddr));
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = 0;
        bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr));

        SocketContext* ctx = new SocketContext();
        ctx->sock = s;
        ctx->on_write = on_connect;
        
        // RETAIN for Map ownership
        retain_context(ctx);
        m_sockets[s] = ctx;

        CreateIoCompletionPort((HANDLE)s, m_iocp, (ULONG_PTR)ctx, 0);

        memset(&ctx->connect_io.overlapped, 0, sizeof(OVERLAPPED));
        ctx->connect_io.type = IO_CONNECT;
        
        // RETAIN for IO
        retain_context(ctx);

        if (m_lpfnConnectEx) {
            BOOL ret = m_lpfnConnectEx(s, (sockaddr*)&addr, sizeof(addr), NULL, 0, NULL, &ctx->connect_io.overlapped);
            if (!ret && WSAGetLastError() != ERROR_IO_PENDING) {
                // Immediate failure
                release_context(ctx);
            }
        } else {
             // Should not happen if init correctly
             release_context(ctx);
        }
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::queue_task(std::function<void()> task) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back(task);
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::pause_read(SOCKET s) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) {
            it->second->paused = true;
        }
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::resume_read(SOCKET s) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) {
            SocketContext* ctx = it->second;
            if (ctx->paused) {
                ctx->paused = false;
                // If no read is pending, we must kickstart it
                if (!ctx->read_pending) {
                    post_zero_byte_read(ctx);
                }
            }
        }
    });
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
                try {
                    task();
                } catch (const std::exception& e) {
                    printf("Worker task exception: %s\n", e.what());
                } catch (...) {
                    printf("Worker task unknown exception\n");
                }
            }
        }

        // 2. Wait for Completion
        BOOL ret = GetQueuedCompletionStatus(m_iocp, &bytesTransferred, &completionKey, &overlapped, 10);

        if (overlapped != NULL) {
            SocketContext* ctx = (SocketContext*)completionKey;
            IO_CONTEXT* ioCtx = (IO_CONTEXT*)overlapped;

            // SAFETY CHECK: Verify Context Validity
            if (!ctx || ctx->magic != SocketContext::MAGIC_VAL) {
                printf("Worker: Bad/Deleted Context! Magic: 0x%x Addr: %p\n", ctx ? ctx->magic : 0, ctx);
                continue; 
            }

            try {
                if (ret) {
                    // Success
                    if (ioCtx->type == IO_READ) {
                        ctx->read_pending = false;
                        if (ctx->on_read) ctx->on_read();
                        
                        // Re-post only if socket still alive in map AND NOT PAUSED
                        if (m_sockets.find(ctx->sock) != m_sockets.end()) {
                            if (!ctx->paused) {
                                post_zero_byte_read(ctx);
                            }
                        }
                    } else if (ioCtx->type == IO_CONNECT) {
                        setsockopt(ctx->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
                        if (ctx->on_write) ctx->on_write();
                    }
                } else {
                    // Failure (e.g. Cancelled, Connection Refused)
                    if (ioCtx->type == IO_READ) {
                        ctx->read_pending = false;
                        // Trigger read callback to let recv() fail properly
                        if (ctx->on_read) ctx->on_read();
                    } else if (ioCtx->type == IO_CONNECT) {
                        if (ctx->on_write) ctx->on_write();
                    }
                }
            } catch (const std::exception& e) {
                printf("Worker callback exception: %s\n", e.what());
            } catch (...) {
                printf("Worker callback unknown exception\n");
            }
            
            // RELEASE for IO Completion
            // This balances the retain_context called before WSARecv/ConnectEx
            release_context(ctx);
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