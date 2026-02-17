#include "worker.h"
#include "logger.h"
#include "app_config.h"
#include <iostream>
#include <algorithm>



// --- IO_CONTEXT Pool ---
static std::mutex g_io_pool_mtx;
static std::vector<IO_CONTEXT*> g_io_pool;

IO_CONTEXT* acquire_io_context() {
    std::lock_guard<std::mutex> lock(g_io_pool_mtx);
    if (g_io_pool.empty()) {
        return new IO_CONTEXT();
    }
    IO_CONTEXT* io = g_io_pool.back();
    g_io_pool.pop_back();
    memset(&io->overlapped, 0, sizeof(OVERLAPPED));
    io->task = nullptr;
    io->parent = nullptr;
    io->data_len = 0;
    io->write_buffers.clear();
    io->wsa_bufs.clear();
    return io;
}

void release_io_context(IO_CONTEXT* io) {
    if (!io) return;
    io->write_buffers.clear(); // Ensure shared_ptrs are released
    io->wsa_bufs.clear();
    std::lock_guard<std::mutex> lock(g_io_pool_mtx);
    if (g_io_pool.size() < 4096) { // Increased pool size for high throughput
        g_io_pool.push_back(io);
    } else {
        delete io;
    }
}

// --- Worker Implementation ---

Worker::Worker(HANDLE iocp) : m_running(false), m_iocp(iocp) {
}

Worker::~Worker() {
    stop();
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
    PostQueuedCompletionStatus(m_iocp, 0, (ULONG_PTR)this, NULL);
    if (m_thread.joinable()) m_thread.join();
}

void Worker::loop() {
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED overlapped;

    while (m_running) {
        BOOL ret = GetQueuedCompletionStatus(m_iocp, &bytesTransferred, &completionKey, &overlapped, INFINITE);

        if (overlapped == NULL) {
            if (completionKey == (ULONG_PTR)this) break;
            continue;
        }

        IO_CONTEXT* io = (IO_CONTEXT*)overlapped;

        if (io->type == IO_TASK) {
            if (io->task) {
                try { io->task(); } catch (...) { LOG_ERROR("[Worker] Task execution failed."); }
            }
            release_io_context(io);
            continue;
        }

        if (io->type == IO_REMOVE) {
            std::shared_ptr<SocketContext> ctx = WorkerPool::instance().find_context(io->sock);
            if (ctx) {
                ctx->closing = true;
                ctx->on_remove_done = io->task;
                WorkerPool::instance().unregister_context(io->sock);
                closesocket(io->sock);
                
                if (ctx.use_count() == 1) {
                    if (ctx->on_remove_done) ctx->on_remove_done();
                }
            } else if (io->task) {
                io->task();
            }
            release_io_context(io);
            continue;
        }

        std::shared_ptr<SocketContext> ctx = io->parent;
        if (!ctx) {
            release_io_context(io);
            continue;
        }

        if (!ctx->closing) {
            if (ret) {
                if (io->type == IO_READ) {
                    if (bytesTransferred > 0) {
                        if (ctx->on_read) ctx->on_read((char*)io->buf, (int)bytesTransferred, ctx->is_udp ? &io->remote_addr : nullptr);
                    } else {
                        if (ctx->on_read) ctx->on_read(nullptr, 0, nullptr);
                    }
                } else if (io->type == IO_WRITE) {
                    if (ctx->on_write) ctx->on_write((int)bytesTransferred);
                } else if (io->type == IO_CONNECT) {
                    setsockopt(ctx->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
                    if (io->task) io->task();
                    if (ctx->on_read) {
                        for (int i = 0; i < CONCURRENT_READ_COUNT; ++i) {
                            WorkerPool::instance().post_read(ctx);
                        }
                    }
                }
            } else {
                if (io->type == IO_READ) {
                    if (ctx->on_read) ctx->on_read(nullptr, -1, nullptr);
                } else if (io->type == IO_WRITE && ctx->on_write) {
                    ctx->on_write(-1);
                } else if (io->type == IO_CONNECT) {
                    LOG_ERROR("[Worker] ConnectEx async failure: %d", WSAGetLastError());
                    if (io->task) io->task();
                }
            }
        }

        release_io_context(io);

        if (ctx->closing && ctx.use_count() == 1) {
            if (ctx->on_remove_done) ctx->on_remove_done();
        }
    }
}

// --- WorkerPool Implementation ---

WorkerPool& WorkerPool::instance() {
    static WorkerPool pool;
    return pool;
}

WorkerPool::~WorkerPool() {
    if (m_shared_iocp) CloseHandle(m_shared_iocp);
    for (auto* w : m_workers) delete w;
}

void WorkerPool::init(int count) {
    if (!m_workers.empty()) return;
    m_shared_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    for (int i = 0; i < count; ++i) {
        Worker* w = new Worker(m_shared_iocp);
        w->start(i);
        m_workers.push_back(w);
    }
}

void WorkerPool::add_socket(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read, std::function<void(int)> on_write, bool is_udp) {
    IO_CONTEXT* io = acquire_io_context();
    io->type = IO_TASK;
    io->task = [this, s, on_read, on_write, is_udp]() {
        std::shared_ptr<SocketContext> ctx = find_context(s);
        if (!ctx) {
            ctx = std::make_shared<SocketContext>();
            ctx->sock = s;
            register_context(s, ctx);
            CreateIoCompletionPort((HANDLE)s, m_shared_iocp, (ULONG_PTR)ctx.get(), 0);
        }
        ctx->on_read = on_read;
        ctx->on_write = on_write; 
        ctx->is_udp = is_udp;
        if (on_read) {
            for (int i = 0; i < CONCURRENT_READ_COUNT; ++i) {
                post_read(ctx);
            }
        }
    };
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io);
}

void WorkerPool::remove_socket(SOCKET s, std::function<void()> on_done) {
    IO_CONTEXT* io = acquire_io_context();
    io->type = IO_REMOVE;
    io->sock = s;
    io->task = on_done;
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io);
}

void WorkerPool::connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect, 
                                  std::function<void(char*, int, sockaddr_in*)> on_read,
                                  std::function<void(int)> on_write) {
    IO_CONTEXT* init_task = acquire_io_context();
    init_task->type = IO_TASK;
    init_task->task = [this, s, addr, on_connect, on_read, on_write]() {
        struct sockaddr_in bindAddr;
        memset(&bindAddr, 0, sizeof(bindAddr));
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = 0;
        bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr));

        std::shared_ptr<SocketContext> ctx = find_context(s);
        if (!ctx) {
            ctx = std::make_shared<SocketContext>();
            ctx->sock = s;
            register_context(s, ctx);
            CreateIoCompletionPort((HANDLE)s, m_shared_iocp, (ULONG_PTR)ctx.get(), 0);
        }
        ctx->on_read = on_read;
        ctx->on_write = on_write;

        LPFN_CONNECTEX ConnectExPtr = nullptr;
        GUID guid = WSAID_CONNECTEX;
        DWORD bytes = 0;
        WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &ConnectExPtr, sizeof(ConnectExPtr), &bytes, NULL, NULL);

        if (ConnectExPtr) {
            IO_CONTEXT* io = acquire_io_context();
            io->type = IO_CONNECT;
            io->sock = s;
            io->parent = ctx;
            io->task = on_connect;
            BOOL ret = ConnectExPtr(s, (sockaddr*)&addr, sizeof(addr), NULL, 0, NULL, &io->overlapped);
            if (!ret && WSAGetLastError() != ERROR_IO_PENDING) {
                if (io->task) io->task();
                release_io_context(io);
            }
        } else {
            LOG_ERROR("[WorkerPool] Failed to get ConnectEx pointer.");
        }
    };
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)init_task);
}

bool WorkerPool::send_async(SOCKET s, const uint8_t* data, size_t len) {
    if (len == 0) return true;
    auto ctx = find_context(s);
    if (ctx && !ctx->closing) {
        post_write(ctx, data, len);
        return true;
    }
    return false;
}

bool WorkerPool::send_async(SOCKET s, char* buf, int len) {
    if (len <= 0) return true;
    return send_async(s, (const uint8_t*)buf, (size_t)len);
}

bool WorkerPool::send_async(SOCKET s, std::shared_ptr<std::vector<char>> buffer) {
    if (!buffer || buffer->empty()) return true;
    auto ctx = find_context(s);
    if (ctx && !ctx->closing) {
        std::vector<std::shared_ptr<std::vector<char>>> buffers;
        buffers.push_back(buffer);
        post_write(ctx, std::move(buffers));
        return true;
    }
    return false;
}

bool WorkerPool::send_batch_async(SOCKET s, std::vector<std::shared_ptr<std::vector<char>>> buffers) {
    if (buffers.empty()) return true;
    auto ctx = find_context(s);
    if (ctx && !ctx->closing) {
        post_write(ctx, std::move(buffers));
        return true;
    }
    return false;
}

void WorkerPool::read_async(SOCKET s) {
    IO_CONTEXT* io_task = acquire_io_context();
    io_task->type = IO_TASK;
    io_task->task = [this, s]() {
        auto ctx = find_context(s);
        if (ctx) post_read(ctx);
    };
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io_task);
}

void WorkerPool::update_read_callback(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read) {
    IO_CONTEXT* io_task = acquire_io_context();
    io_task->type = IO_TASK;
    io_task->task = [this, s, on_read]() {
        auto ctx = find_context(s);
        if (ctx) ctx->on_read = on_read;
    };
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io_task);
}

void WorkerPool::queue_task(std::function<void()> task) {
    IO_CONTEXT* io = acquire_io_context();
    io->type = IO_TASK;
    io->task = std::move(task);
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io);
}

std::shared_ptr<SocketContext> WorkerPool::find_context(SOCKET s) {
    auto& shard = m_shards[s % NUM_SHARDS];
    std::lock_guard<std::mutex> lock(shard.mtx);
    auto it = shard.sockets.find(s);
    return (it != shard.sockets.end()) ? it->second : nullptr;
}

void WorkerPool::register_context(SOCKET s, std::shared_ptr<SocketContext> ctx) {
    auto& shard = m_shards[s % NUM_SHARDS];
    std::lock_guard<std::mutex> lock(shard.mtx);
    shard.sockets[s] = ctx;
}

void WorkerPool::unregister_context(SOCKET s) {
    auto& shard = m_shards[s % NUM_SHARDS];
    std::lock_guard<std::mutex> lock(shard.mtx);
    shard.sockets.erase(s);
}

void WorkerPool::post_read(const std::shared_ptr<SocketContext>& ctx) {
    if (!ctx || ctx->closing) return;

    IO_CONTEXT* io = acquire_io_context();
    io->type = IO_READ;
    io->sock = ctx->sock;
    io->parent = ctx;

    WSABUF w;
    w.buf = (char*)io->buf;
    w.len = sizeof(io->buf);
    io->wsa_bufs.push_back(w);

    DWORD bytes = 0, flags = 0;
    int ret;
    if (ctx->is_udp) {
        io->remote_addr_len = sizeof(io->remote_addr);
        ret = WSARecvFrom(ctx->sock, io->wsa_bufs.data(), 1, &bytes, &flags, (sockaddr*)&io->remote_addr, &io->remote_addr_len, &io->overlapped, NULL);
    } else {
        ret = WSARecv(ctx->sock, io->wsa_bufs.data(), 1, &bytes, &flags, &io->overlapped, NULL);
    }

    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        release_io_context(io);
    }
}

void WorkerPool::post_write(const std::shared_ptr<SocketContext>& ctx, std::vector<std::shared_ptr<std::vector<char>>> buffers) {
    if (!ctx || ctx->closing || buffers.empty()) return;

    IO_CONTEXT* io = acquire_io_context();
    io->type = IO_WRITE;
    io->sock = ctx->sock;
    io->parent = ctx;
    io->write_buffers = std::move(buffers);

    io->wsa_bufs.reserve(io->write_buffers.size());
    for (auto& buf : io->write_buffers) {
        WSABUF w;
        w.buf = buf->data();
        w.len = (ULONG)buf->size();
        io->wsa_bufs.push_back(w);
    }

    DWORD bytes = 0;
    int ret = WSASend(ctx->sock, io->wsa_bufs.data(), (DWORD)io->wsa_bufs.size(), &bytes, 0, &io->overlapped, NULL);

    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        if (ctx->on_write) ctx->on_write(-1);
        release_io_context(io);
    }
}


void WorkerPool::post_write(const std::shared_ptr<SocketContext>& ctx, const uint8_t* data, size_t len) {
    if (!ctx || ctx->closing || len == 0) return;

    IO_CONTEXT* io = acquire_io_context();
    io->type = IO_WRITE;
    io->sock = ctx->sock;
    io->parent = ctx;
    
    size_t copy_len = (std::min)(len, sizeof(io->buf));
    memcpy(io->buf, data, copy_len);
    io->data_len = copy_len;

    WSABUF w;
    w.buf = (char*)io->buf;
    w.len = (ULONG)io->data_len;
    io->wsa_bufs.push_back(w);

    DWORD bytes = 0;
    int ret = WSASend(ctx->sock, io->wsa_bufs.data(), (DWORD)io->wsa_bufs.size(), &bytes, 0, &io->overlapped, NULL);

    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        if (ctx->on_write) ctx->on_write(-1);
        release_io_context(io);
    }
}
