#include "worker.h"
#include "logger.h"
#include <iostream>
#include <algorithm>

// Worker Implementation

Worker::Worker(HANDLE iocp) : m_running(false), m_iocp(iocp), m_lpfnConnectEx(NULL) {
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
}

void Worker::start(int core_index) {
    if (m_running) return;
    m_running = true;
    m_thread = std::thread(&Worker::loop, this);
    SetThreadPriority(m_thread.native_handle(), THREAD_PRIORITY_ABOVE_NORMAL);

    if (core_index >= 0) {
        DWORD_PTR mask = (static_cast<DWORD_PTR>(1) << (core_index % (sizeof(DWORD_PTR) * 8)));
        SetThreadAffinityMask(m_thread.native_handle(), mask);
    }
}

void Worker::stop() {
    if (!m_running) return;
    m_running = false;
    // Post a control message to wake up the loop
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
    if (m_thread.joinable()) m_thread.join();
}

void Worker::post_read(SocketContext* ctx) {
    if (!ctx || ctx->closing || ctx->paused || ctx->magic != SocketContext::MAGIC_VAL) return;

    if (ctx->read_pending.exchange(true)) return; 

    IO_CONTEXT* io = new IO_CONTEXT();
    io->type = IO_READ;
    io->sock = ctx->sock;
    io->parent = ctx;
    io->buf.resize(65536); // 64KB for high throughput

    WSABUF wsaBuf;
    wsaBuf.buf = (char*)io->buf.data();
    wsaBuf.len = (ULONG)io->buf.size();

    ctx->pending_io++;

    DWORD bytes = 0;
    DWORD flags = 0;
    int ret;

    if (ctx->is_udp) {
        io->remote_addr_len = sizeof(io->remote_addr);
        ret = WSARecvFrom(ctx->sock, &wsaBuf, 1, &bytes, &flags, (sockaddr*)&io->remote_addr, &io->remote_addr_len, &io->overlapped, NULL);
    } else {
        ret = WSARecv(ctx->sock, &wsaBuf, 1, &bytes, &flags, &io->overlapped, NULL);
    }

    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        ctx->pending_io--;
        ctx->read_pending = false;
        delete io;
    }
}

void Worker::post_write(SocketContext* ctx, std::vector<uint8_t>&& data) {
    if (!ctx || ctx->closing || ctx->magic != SocketContext::MAGIC_VAL || data.empty()) return;

    IO_CONTEXT* io = new IO_CONTEXT();
    io->type = IO_WRITE;
    io->sock = ctx->sock;
    io->parent = ctx;
    io->buf = std::move(data);

    WSABUF wsaBuf;
    wsaBuf.buf = (char*)io->buf.data();
    wsaBuf.len = (ULONG)io->buf.size();

    ctx->pending_io++;

    DWORD bytes = 0;
    int ret = WSASend(ctx->sock, &wsaBuf, 1, &bytes, 0, &io->overlapped, NULL);

    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        ctx->pending_io--;
        auto on_write = ctx->on_write;
        if (on_write) on_write(-1);
        delete io;
    }
}

void Worker::add_socket(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read, std::function<void(int)> on_write, std::function<void()> on_close, bool is_udp) {
    IO_CONTEXT* io = new IO_CONTEXT();
    io->type = IO_TASK;
    io->task = [this, s, on_read, on_write, on_close, is_udp]() {
        SocketContext* ctx = new SocketContext();
        ctx->sock = s;
        ctx->on_read = on_read;
        ctx->on_write = on_write; 
        ctx->on_close = on_close;
        ctx->is_udp = is_udp;

        m_sockets[s] = ctx;
        CreateIoCompletionPort((HANDLE)s, m_iocp, (ULONG_PTR)ctx, 0);

        if (on_read) {
            post_read(ctx);
        }
    };
    PostQueuedCompletionStatus(m_iocp, 0, 0, (LPOVERLAPPED)io);
}

void Worker::remove_socket(SOCKET s, std::function<void()> on_done) {
    IO_CONTEXT* io = new IO_CONTEXT();
    io->type = IO_REMOVE;
    io->sock = s;
    io->task = on_done;
    PostQueuedCompletionStatus(m_iocp, 0, 0, (LPOVERLAPPED)io);
}

void Worker::connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect) {
    IO_CONTEXT* io_task = new IO_CONTEXT();
    io_task->type = IO_TASK;
    io_task->task = [this, s, addr, on_connect]() {
        struct sockaddr_in bindAddr;
        memset(&bindAddr, 0, sizeof(bindAddr));
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = 0;
        bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr));

        SocketContext* ctx = new SocketContext();
        ctx->sock = s;
        m_sockets[s] = ctx;
        CreateIoCompletionPort((HANDLE)s, m_iocp, (ULONG_PTR)ctx, 0);

        IO_CONTEXT* io = new IO_CONTEXT();
        io->type = IO_CONNECT;
        io->sock = s;
        io->parent = ctx;
        io->task = on_connect;

        ctx->pending_io++;
        if (m_lpfnConnectEx) {
            BOOL ret = m_lpfnConnectEx(s, (sockaddr*)&addr, sizeof(addr), NULL, 0, NULL, &io->overlapped);
            if (!ret && WSAGetLastError() != ERROR_IO_PENDING) {
                ctx->pending_io--;
                m_sockets.erase(s);
                closesocket(s);
                delete ctx;
                delete io;
            }
        }
    };
    PostQueuedCompletionStatus(m_iocp, 0, 0, (LPOVERLAPPED)io_task);
}

bool Worker::send_async(SOCKET s, char* buf, int len) {
    return send_async(s, std::vector<uint8_t>(buf, buf + len));
}

bool Worker::send_async(SOCKET s, std::vector<uint8_t>&& data) {
    // Note: To avoid locks in the hot path, we could post this as a task,
    // but looking up the context here is faster if the map isn't too large.
    // However, per requirements, we'll post it as a task to be handled by GetQueuedCompletionStatus.
    IO_CONTEXT* io_task = new IO_CONTEXT();
    io_task->type = IO_TASK;
    io_task->sock = s;
    io_task->buf = std::move(data);
    io_task->task = [this, s, moved_io = io_task]() mutable {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end() && !it->second->closing) {
            post_write(it->second, std::move(moved_io->buf));
        }
    };
    PostQueuedCompletionStatus(m_iocp, 0, 0, (LPOVERLAPPED)io_task);
    return true;
}

void Worker::read_async(SOCKET s) {
    IO_CONTEXT* io_task = new IO_CONTEXT();
    io_task->type = IO_TASK;
    io_task->task = [this, s]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) post_read(it->second);
    };
    PostQueuedCompletionStatus(m_iocp, 0, 0, (LPOVERLAPPED)io_task);
}

void Worker::update_read_callback(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read) {
    IO_CONTEXT* io_task = new IO_CONTEXT();
    io_task->type = IO_TASK;
    io_task->task = [this, s, on_read]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) it->second->on_read = on_read;
    };
    PostQueuedCompletionStatus(m_iocp, 0, 0, (LPOVERLAPPED)io_task);
}

void Worker::queue_task(std::function<void()> task) {
    IO_CONTEXT* io = new IO_CONTEXT();
    io->type = IO_TASK;
    io->task = std::move(task);
    PostQueuedCompletionStatus(m_iocp, 0, 0, (LPOVERLAPPED)io);
}

void Worker::set_socket_user_data(SOCKET s, void* user_data) {
    IO_CONTEXT* io_task = new IO_CONTEXT();
    io_task->type = IO_TASK;
    io_task->task = [this, s, user_data]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) it->second->user_data = user_data;
    };
    PostQueuedCompletionStatus(m_iocp, 0, 0, (LPOVERLAPPED)io_task);
}

void Worker::loop() {
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED overlapped;

    while (m_running) {
        // Standard IOCP wait: INFINITE timeout, no polling
        BOOL ret = GetQueuedCompletionStatus(m_iocp, &bytesTransferred, &completionKey, &overlapped, INFINITE);

        if (overlapped == NULL) continue;

        IO_CONTEXT* io = (IO_CONTEXT*)overlapped;

        // Handle generic tasks or control messages
        if (io->type == IO_TASK) {
            if (io->task) {
                try { io->task(); } catch(...) {}
            }
            delete io;
            continue;
        }

        if (io->type == IO_REMOVE) {
            auto it = m_sockets.find(io->sock);
            if (it != m_sockets.end()) {
                SocketContext* ctx = it->second;
                ctx->closing = true;
                ctx->on_remove_done = io->task; // Reuse task field for on_done callback
                m_sockets.erase(it);
                closesocket(io->sock);
                
                if (ctx->pending_io == 0) {
                    if (ctx->on_remove_done) ctx->on_remove_done();
                    delete ctx;
                }
            } else if (io->task) {
                io->task();
            }
            delete io;
            continue;
        }

        SocketContext* ctx = (SocketContext*)completionKey;
        if (!ctx || ctx->magic != SocketContext::MAGIC_VAL) {
            delete io;
            continue;
        }

        ctx->pending_io--;

        if (!ctx->closing) {
            if (ret) {
                if (io->type == IO_READ) {
                    ctx->read_pending = false;
                    if (bytesTransferred > 0) {
                        if (ctx->on_read) ctx->on_read((char*)io->buf.data(), (int)bytesTransferred, ctx->is_udp ? &io->remote_addr : nullptr);
                        post_read(ctx);
                    } else {
                        if (ctx->on_read) ctx->on_read(nullptr, 0, nullptr);
                    }
                } else if (io->type == IO_WRITE) {
                    if (ctx->on_write) ctx->on_write((int)bytesTransferred);
                } else if (io->type == IO_CONNECT) {
                    setsockopt(ctx->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
                    if (io->task) io->task(); // Reuse task field for on_connect callback
                    post_read(ctx);
                }
            } else {
                if (io->type == IO_READ) {
                    ctx->read_pending = false;
                    if (ctx->on_read) ctx->on_read(nullptr, -1, nullptr);
                } else if (io->type == IO_WRITE && ctx->on_write) {
                    ctx->on_write(-1);
                }
            }
        }

        delete io;

        if (ctx->closing && ctx->pending_io == 0) {
            if (ctx->on_remove_done) ctx->on_remove_done();
            delete ctx;
        }
    }
}

// WorkerPool Implementation

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
    
    // Create single shared IOCP for all workers
    m_shared_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    
    for (int i = 0; i < count; ++i) {
        Worker* w = new Worker(m_shared_iocp);
        w->start(i);
        m_workers.push_back(w);
    }
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