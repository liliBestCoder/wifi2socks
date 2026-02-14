#include "worker.h"
#include "logger.h"
#include <iostream>
#include <algorithm>

// Worker Implementation

Worker::Worker() : m_running(false), m_iocp(NULL), m_lpfnConnectEx(NULL) {
    m_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    
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
    SetThreadPriority(m_thread.native_handle(), THREAD_PRIORITY_ABOVE_NORMAL);

    if (core_index >= 0) {
        DWORD_PTR mask = (static_cast<DWORD_PTR>(1) << (core_index % (sizeof(DWORD_PTR) * 8)));
        SetThreadAffinityMask(m_thread.native_handle(), mask);
    }
}

void Worker::stop() {
    if (!m_running) return;
    m_running = false;
    if (m_iocp) PostQueuedCompletionStatus(m_iocp, 0, (ULONG_PTR)this, NULL);
    if (m_thread.joinable()) m_thread.join();
}

void Worker::post_read(SocketContext* ctx) {
    if (!ctx || ctx->closing || ctx->paused || ctx->magic != SocketContext::MAGIC_VAL) return;

    // Maintain a high-performance pipeline by having exactly one large read pending.
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
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, on_read, on_write, on_close, is_udp]() {
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
    });
    PostQueuedCompletionStatus(m_iocp, 0, (ULONG_PTR)this, NULL);
}

void Worker::remove_socket(SOCKET s, std::function<void()> on_done) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_sockets.find(s);
    if (it != m_sockets.end()) {
        SocketContext* ctx = it->second;
        ctx->closing = true;
        ctx->on_remove_done = on_done;
        m_sockets.erase(it);
        closesocket(s);
        
        if (ctx->pending_io == 0) {
            if (ctx->on_remove_done) ctx->on_remove_done();
            delete ctx;
        }
    } else if (on_done) {
        on_done();
    }
}

void Worker::connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, addr, on_connect]() {
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
        io->on_done = on_connect;

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
    });
    PostQueuedCompletionStatus(m_iocp, 0, (ULONG_PTR)this, NULL);
}

bool Worker::send_async(SOCKET s, char* buf, int len) {
    return send_async(s, std::vector<uint8_t>(buf, buf + len));
}

bool Worker::send_async(SOCKET s, std::vector<uint8_t>&& data) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_sockets.find(s);
    if (it != m_sockets.end() && !it->second->closing) {
        post_write(it->second, std::move(data));
        return true;
    }
    return false;
}

void Worker::read_async(SOCKET s) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_sockets.find(s);
    if (it != m_sockets.end()) post_read(it->second);
}

void Worker::update_read_callback(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_sockets.find(s);
    if (it != m_sockets.end()) it->second->on_read = on_read;
}

void Worker::queue_task(std::function<void()> task) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back(task);
    PostQueuedCompletionStatus(m_iocp, 0, (ULONG_PTR)this, NULL);
}

void Worker::set_socket_user_data(SOCKET s, void* user_data) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_sockets.find(s);
    if (it != m_sockets.end()) it->second->user_data = user_data;
}

void Worker::pause_read(SOCKET s) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_sockets.find(s);
    if (it != m_sockets.end()) it->second->paused = true;
}

void Worker::resume_read(SOCKET s) {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_sockets.find(s);
    if (it != m_sockets.end()) {
        it->second->paused = false;
        post_read(it->second);
    }
}

void Worker::loop() {
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED overlapped;

    while (m_running) {
        std::vector<std::function<void()>> current_tasks;
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            if (!m_task_queue.empty()) current_tasks.swap(m_task_queue);
        }
        for (auto& task : current_tasks) {
            try { task(); } catch(...) {}
        }

        DWORD timeout = current_tasks.empty() ? 100 : 0;
        BOOL ret = GetQueuedCompletionStatus(m_iocp, &bytesTransferred, &completionKey, &overlapped, timeout);

        if (overlapped == NULL) continue;

        if (completionKey == (ULONG_PTR)this) {
            continue;
        }

        IO_CONTEXT* io = (IO_CONTEXT*)overlapped;
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
                    if (io->on_done) io->on_done();
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
}

Worker* WorkerPool::get_next_worker() {
    static std::atomic<size_t> next_idx(0);
    if (m_workers.empty()) return nullptr;
    return m_workers[next_idx++ % m_workers.size()];
}
