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

void Worker::start(int core_index) {
    if (m_running) return;
    m_running = true;
    m_thread = std::thread(&Worker::loop, this);
    SetThreadPriority(m_thread.native_handle(), THREAD_PRIORITY_HIGHEST);

    if (core_index >= 0) {
        DWORD_PTR mask = (static_cast<DWORD_PTR>(1) << (core_index % (sizeof(DWORD_PTR) * 8)));
        SetThreadAffinityMask(m_thread.native_handle(), mask);
    }
}

void Worker::stop() {
    if (!m_running) return;
    m_running = false;
    if (m_iocp) PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
    if (m_thread.joinable()) m_thread.join();
}

void Worker::retain_context(SocketContext* ctx) {
    if (ctx) ctx->pending_io++;
}

void Worker::release_context(SocketContext* ctx) {
    if (ctx) ctx->pending_io--;
}

void Worker::post_read(SocketContext* ctx) {
    if (!ctx || ctx->read_pending || ctx->closing || ctx->magic != SocketContext::MAGIC_VAL) return;

    DWORD bytes = 0;
    DWORD flags = 0;
    
    memset(&ctx->read_io.overlapped, 0, sizeof(OVERLAPPED));
    ctx->read_io.type = IO_READ;
    ctx->read_io.sock = ctx->sock;

    ctx->wsaBuf.buf = ctx->buffer;
    ctx->wsaBuf.len = sizeof(ctx->buffer);

    ctx->pending_io++;

    int ret = SOCKET_ERROR;

    if (ctx->is_udp) {
        ctx->remote_addr_len = sizeof(ctx->remote_addr);
        ret = WSARecvFrom(ctx->sock, &ctx->wsaBuf, 1, &bytes, &flags, (sockaddr*)&ctx->remote_addr, &ctx->remote_addr_len, &ctx->read_io.overlapped, NULL);
    } else {
        ret = WSARecv(ctx->sock, &ctx->wsaBuf, 1, &bytes, &flags, &ctx->read_io.overlapped, NULL);
    }

    if (ret == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            ctx->pending_io--;
        } else {
            ctx->read_pending = true;
        }
    } else {
        ctx->read_pending = true;
    }
}

void Worker::post_write(SocketContext* ctx, std::vector<uint8_t>&& data) {
    if (!ctx || ctx->closing || ctx->magic != SocketContext::MAGIC_VAL) return;

    if (ctx->write_pending) {
        ctx->write_queue.push(std::move(data));
        return;
    }

    memset(&ctx->write_io.overlapped, 0, sizeof(OVERLAPPED));
    ctx->write_io.type = IO_WRITE;
    ctx->write_io.sock = ctx->sock;
    
    ctx->write_io.buf = std::move(data);
    ctx->wsaWriteBuf.buf = (char*)ctx->write_io.buf.data();
    ctx->wsaWriteBuf.len = (ULONG)ctx->write_io.buf.size();

    ctx->pending_io++;
    ctx->write_pending = true;

    DWORD bytes = 0;
    int ret = WSASend(ctx->sock, &ctx->wsaWriteBuf, 1, &bytes, 0, &ctx->write_io.overlapped, NULL);

    if (ret == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            ctx->write_pending = false;
            ctx->pending_io--;
            auto on_write = ctx->on_write;
            if (on_write) on_write(-1);
            
            // Try to send next if any
            if (!ctx->write_queue.empty()) {
                std::vector<uint8_t> next_data = std::move(ctx->write_queue.front());
                ctx->write_queue.pop();
                post_write(ctx, std::move(next_data));
            }
        }
    }
}

void Worker::add_socket(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read, std::function<void(int)> on_write, std::function<void()> on_close, bool is_udp) {
    std::lock_guard<std::mutex> lock(m_mtx);
    
    m_task_queue.push_back([this, s, on_read, on_write, on_close, is_udp]() {
        SocketContext* ctx = nullptr;
        auto it = m_sockets.find(s);
        bool new_association = false;
        
        if (it != m_sockets.end()) {
            ctx = it->second;
        } else {
            ctx = new SocketContext();
            ctx->sock = s;
            ctx->read_io.sock = s;
            ctx->write_io.sock = s;
            ctx->connect_io.sock = s;
            m_sockets[s] = ctx;
            new_association = true;
        }
        
        ctx->on_read = on_read;
        ctx->on_write = on_write; 
        ctx->on_close = on_close;
        ctx->is_udp = is_udp;

        if (new_association) {
            CreateIoCompletionPort((HANDLE)s, m_iocp, (ULONG_PTR)ctx, 0);
        }

        if (on_read && !ctx->read_pending) {
            post_read(ctx);
        }
    });
    
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::remove_socket(SOCKET s, std::function<void()> on_done) {
    auto* io_ctx = new IO_CONTEXT();
    io_ctx->type = IO_REMOVE;
    io_ctx->sock = s;
    io_ctx->on_done = on_done;
    // completionKey is Worker*, so loop knows it is a control message
    PostQueuedCompletionStatus(m_iocp, 0, (ULONG_PTR)this, &io_ctx->overlapped);
}

void Worker::connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, addr, on_connect]() {
        int flag = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

        struct sockaddr_in bindAddr;
        memset(&bindAddr, 0, sizeof(bindAddr));
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = 0;
        bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr));

        SocketContext* ctx = new SocketContext();
        ctx->sock = s;
        ctx->read_io.sock = s;
        ctx->write_io.sock = s;
        ctx->connect_io.sock = s;

        if (on_connect) {
            ctx->on_write = [on_connect](int status) {
                on_connect();
            };
        }
        
        m_sockets[s] = ctx;

        CreateIoCompletionPort((HANDLE)s, m_iocp, (ULONG_PTR)ctx, 0);

        memset(&ctx->connect_io.overlapped, 0, sizeof(OVERLAPPED));
        ctx->connect_io.type = IO_CONNECT;
        
        ctx->pending_io++; // Track ConnectEx

        if (m_lpfnConnectEx) {
            BOOL ret = m_lpfnConnectEx(s, (sockaddr*)&addr, sizeof(addr), NULL, 0, NULL, &ctx->connect_io.overlapped);
            if (!ret && WSAGetLastError() != ERROR_IO_PENDING) {
                ctx->pending_io--;
                auto it = m_sockets.find(s);
                if (it != m_sockets.end() && it->second == ctx) {
                    m_sockets.erase(it);
                }
                closesocket(ctx->sock);
                delete ctx;
            }
        } else {
             ctx->pending_io--;
             auto it = m_sockets.find(s);
             if (it != m_sockets.end() && it->second == ctx) {
                 m_sockets.erase(it);
             }
             closesocket(ctx->sock);
             delete ctx;
        }
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

bool Worker::send_async(SOCKET s, char* buf, int len) {
    return send_async(s, std::vector<uint8_t>(buf, buf + len));
}

bool Worker::send_async(SOCKET s, std::vector<uint8_t>&& data) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, data = std::move(data)]() mutable {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) {
            post_write(it->second, std::move(data));
        }
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
    return true; 
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
                if (!ctx->read_pending) {
                    post_read(ctx);
                }
            }
        }
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::set_socket_user_data(SOCKET s, void* user_data) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, user_data]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) {
            it->second->user_data = user_data;
        }
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

void Worker::loop() {
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED overlapped;

    while (m_running) {
        {
            std::vector<std::function<void()>> current_tasks;
            {
                std::lock_guard<std::mutex> lock(m_mtx);
                if (!m_task_queue.empty()) {
                    current_tasks.swap(m_task_queue);
                }
            }
            for (auto& task : current_tasks) {
                try { task(); } catch (...) {}
            }
        }

        DWORD timeout = INFINITE;
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            if (!m_task_queue.empty()) timeout = 0;
        }

        BOOL ret = GetQueuedCompletionStatus(m_iocp, &bytesTransferred, &completionKey, &overlapped, timeout);

        if (overlapped != NULL) {
            IO_CONTEXT* ioCtx = (IO_CONTEXT*)overlapped;

            // Handle Control Messages (completionKey == Worker*)
            if (ioCtx->type == IO_REMOVE) {
                auto it = m_sockets.find(ioCtx->sock);
                if (it != m_sockets.end()) {
                    SocketContext* ctx = it->second;
                    ctx->closing = true;
                    ctx->on_remove_done = ioCtx->on_done;
                    m_sockets.erase(it); // Remove from map so no new IO starts
                    
                    // Force close to cancel all pending overlapped IO
                    closesocket(ctx->sock);
                    
                    // If no IO was pending, delete immediately
                    if (ctx->pending_io == 0) {
                        if (ctx->on_remove_done) ctx->on_remove_done();
                        if (ctx->user_data) delete (std::shared_ptr<void>*)ctx->user_data;
                        delete ctx;
                    }
                } else {
                    // Sockets already removed or not found
                    if (ioCtx->on_done) ioCtx->on_done();
                }
                delete ioCtx;
                continue;
            }
            
            SocketContext* ctx = (SocketContext*)completionKey;

            // SAFETY: Validate context integrity
            if (!ctx || ctx->magic != SocketContext::MAGIC_VAL) {
                continue;
            }

            ctx->pending_io--; // An I/O operation returned

            // Only process completion if we are not in the process of closing
            if (!ctx->closing) {
                try {
                    if (ret) {
                        if (ioCtx->type == IO_READ) {
                            ctx->read_pending = false;
                            auto on_read = ctx->on_read; 
                            if (on_read) {
                                on_read(ctx->buffer, (int)bytesTransferred, ctx->is_udp ? &ctx->remote_addr : nullptr);
                            }
                            if (!ctx->closing && !ctx->paused) {
                                post_read(ctx);
                            }
                        } else if (ioCtx->type == IO_CONNECT) {
                            setsockopt(ctx->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
                            auto on_write = ctx->on_write;
                            if (on_write) on_write(0); 
                        } else if (ioCtx->type == IO_WRITE) {
                            ctx->write_pending = false;
                            auto on_write = ctx->on_write;
                            if (on_write) on_write((int)bytesTransferred);

                            // Check write queue
                            if (!ctx->closing && !ctx->write_queue.empty()) {
                                std::vector<uint8_t> next_data = std::move(ctx->write_queue.front());
                                ctx->write_queue.pop();
                                post_write(ctx, std::move(next_data));
                            }
                        }
                    } else {
                        // Error completion
                        if (ioCtx->type == IO_READ) {
                            ctx->read_pending = false;
                            auto on_read = ctx->on_read;
                            if (on_read) on_read(nullptr, 0, nullptr);
                        } else if (ioCtx->type == IO_CONNECT) {
                            auto on_write = ctx->on_write;
                            if (on_write) on_write(-1); 
                        } else if (ioCtx->type == IO_WRITE) {
                            ctx->write_pending = false;
                            auto on_write = ctx->on_write;
                            if (on_write) on_write(-1); 

                            // Still try to clear queue or just let it be? 
                            // Usually a failed write means the socket is bad.
                        }
                    }
                } catch (...) {}
            }

            // SCHEME A: FINAL CLEANUP
            // If the connection was marked for closing AND all pending IO have returned
            if (ctx->closing && ctx->pending_io == 0) {
                if (ctx->on_remove_done) ctx->on_remove_done();
                if (ctx->user_data) delete (std::shared_ptr<void>*)ctx->user_data;
                delete ctx;
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
        w->start(i);
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

void Worker::read_async(SOCKET s) {
    queue_task([this, s]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) {
            post_read(it->second);
        }
    });
}

void Worker::update_read_callback(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read) {
    queue_task([this, s, on_read]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) {
            it->second->on_read = on_read;
        }
    });
}