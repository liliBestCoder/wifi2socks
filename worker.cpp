#include "worker.h"
#include "logger.h"
#include "app_config.h"
#include <iostream>
#include <algorithm>

// Worker Implementation

Worker::Worker(HANDLE iocp) : m_running(false), m_iocp(iocp) {
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
    PostQueuedCompletionStatus(m_iocp, 0, (ULONG_PTR)this, NULL);
    if (m_thread.joinable()) m_thread.join();
}

void Worker::loop() {
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED overlapped;

    while (m_running) {
        // 标准 IOCP 等待：无轮询，由内核唤醒
        BOOL ret = GetQueuedCompletionStatus(m_iocp, &bytesTransferred, &completionKey, &overlapped, INFINITE);

        if (overlapped == NULL) {
            // 处理退出信号
            if (completionKey == (ULONG_PTR)this) break;
            continue;
        }

        IO_CONTEXT* io = (IO_CONTEXT*)overlapped;

        // 【关键修复】优先处理任务类型，不再受 completionKey 为 NULL 的限制
        if (io->type == IO_TASK) {
            if (io->task) {
                try { io->task(); } catch (...) { LOG_ERROR("[Worker] Task execution failed."); }
            }
            delete io;
            continue;
        }

        // 处理 Socket 移除逻辑
        if (io->type == IO_REMOVE) {
            SocketContext* ctx = WorkerPool::instance().find_context(io->sock);
            if (ctx) {
                ctx->closing = true;
                ctx->on_remove_done = io->task;
                WorkerPool::instance().unregister_context(io->sock);
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
                        // 读到数据，执行回调
                        if (ctx->on_read) ctx->on_read((char*)io->buf.data(), (int)bytesTransferred, ctx->is_udp ? &io->remote_addr : nullptr);
                        // 立即挂起下一个读，保持流水线吞吐
                        WorkerPool::instance().post_read(ctx);
                    } else {
                        // 对方关闭连接
                        if (ctx->on_read) ctx->on_read(nullptr, 0, nullptr);
                    }
                } else if (io->type == IO_WRITE) {
                    if (ctx->on_write) ctx->on_write((int)bytesTransferred);
                } else if (io->type == IO_CONNECT) {
                    setsockopt(ctx->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
                    if (io->task) io->task();
                    WorkerPool::instance().post_read(ctx);
                }
            } else {
                // 处理错误情况
                if (io->type == IO_READ) {
                    ctx->read_pending = false;
                    if (ctx->on_read) ctx->on_read(nullptr, -1, nullptr);
                } else if (io->type == IO_WRITE && ctx->on_write) {
                    ctx->on_write(-1);
                }
            }
        }

        delete io;

        // 最终清理：当所有 pending IO 都返回且连接已标记关闭
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
    m_shared_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    for (int i = 0; i < count; ++i) {
        Worker* w = new Worker(m_shared_iocp);
        w->start(i);
        m_workers.push_back(w);
    }
}

void WorkerPool::add_socket(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read, std::function<void(int)> on_write, std::function<void()> on_close, bool is_udp) {
    IO_CONTEXT* io = new IO_CONTEXT();
    io->type = IO_TASK;
    io->task = [this, s, on_read, on_write, on_close, is_udp]() {
        SocketContext* ctx = new SocketContext();
        ctx->sock = s;
        ctx->on_read = on_read;
        ctx->on_write = on_write; 
        ctx->on_close = on_close;
        ctx->is_udp = is_udp;
        register_context(s, ctx);
        CreateIoCompletionPort((HANDLE)s, m_shared_iocp, (ULONG_PTR)ctx, 0);
        if (on_read) post_read(ctx);
    };
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io);
}

void WorkerPool::remove_socket(SOCKET s, std::function<void()> on_done) {
    IO_CONTEXT* io = new IO_CONTEXT();
    io->type = IO_REMOVE;
    io->sock = s;
    io->task = on_done;
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io);
}

void WorkerPool::connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect) {
    // 首先投递一个创建上下文并绑定 IOCP 的任务
    IO_CONTEXT* init_task = new IO_CONTEXT();
    init_task->type = IO_TASK;
    init_task->task = [this, s, addr, on_connect]() {
        struct sockaddr_in bindAddr;
        memset(&bindAddr, 0, sizeof(bindAddr));
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = 0;
        bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr));

        SocketContext* ctx = new SocketContext();
        ctx->sock = s;
        register_context(s, ctx);
        CreateIoCompletionPort((HANDLE)s, m_shared_iocp, (ULONG_PTR)ctx, 0);

        // 获取 ConnectEx 指针 (通常在全局初始化或 Worker 构造中完成，这里简化处理)
        LPFN_CONNECTEX ConnectExPtr = nullptr;
        GUID guid = WSAID_CONNECTEX;
        DWORD bytes = 0;
        WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &ConnectExPtr, sizeof(ConnectExPtr), &bytes, NULL, NULL);

        if (ConnectExPtr) {
            IO_CONTEXT* io = new IO_CONTEXT();
            io->type = IO_CONNECT;
            io->sock = s;
            io->parent = ctx;
            io->task = on_connect;
            ctx->pending_io++;
            BOOL ret = ConnectExPtr(s, (sockaddr*)&addr, sizeof(addr), NULL, 0, NULL, &io->overlapped);
            if (!ret && WSAGetLastError() != ERROR_IO_PENDING) {
                ctx->pending_io--;
                unregister_context(s);
                closesocket(s);
                delete ctx;
                delete io;
            }
        }
    };
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)init_task);
}

bool WorkerPool::send_async(SOCKET s, std::vector<uint8_t>&& data) {
    IO_CONTEXT* io_task = new IO_CONTEXT();
    io_task->type = IO_TASK;
    io_task->buf = std::move(data);
    io_task->task = [this, s, moved_io = io_task]() mutable {
        SocketContext* ctx = find_context(s);
        if (ctx && !ctx->closing) {
            post_write(ctx, std::move(moved_io->buf));
        }
    };
    return PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io_task) != FALSE;
}

bool WorkerPool::send_async(SOCKET s, char* buf, int len) {
    return send_async(s, std::vector<uint8_t>(buf, buf + len));
}

void WorkerPool::read_async(SOCKET s) {
    IO_CONTEXT* io_task = new IO_CONTEXT();
    io_task->type = IO_TASK;
    io_task->task = [this, s]() {
        SocketContext* ctx = find_context(s);
        if (ctx) post_read(ctx);
    };
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io_task);
}

void WorkerPool::update_read_callback(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read) {
    IO_CONTEXT* io_task = new IO_CONTEXT();
    io_task->type = IO_TASK;
    io_task->task = [this, s, on_read]() {
        SocketContext* ctx = find_context(s);
        if (ctx) ctx->on_read = on_read;
    };
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io_task);
}

void WorkerPool::queue_task(std::function<void()> task) {
    IO_CONTEXT* io = new IO_CONTEXT();
    io->type = IO_TASK;
    io->task = std::move(task);
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io);
}

SocketContext* WorkerPool::find_context(SOCKET s) {
    std::lock_guard<std::mutex> lock(m_global_mtx);
    auto it = m_global_sockets.find(s);
    return (it != m_global_sockets.end()) ? it->second : nullptr;
}

void WorkerPool::register_context(SOCKET s, SocketContext* ctx) {
    std::lock_guard<std::mutex> lock(m_global_mtx);
    m_global_sockets[s] = ctx;
}

void WorkerPool::unregister_context(SOCKET s) {
    std::lock_guard<std::mutex> lock(m_global_mtx);
    m_global_sockets.erase(s);
}

void WorkerPool::post_read(SocketContext* ctx) {
    if (!ctx || ctx->closing || ctx->magic != SocketContext::MAGIC_VAL) return;
    if (ctx->read_pending.exchange(true)) return;

    IO_CONTEXT* io = new IO_CONTEXT();
    io->type = IO_READ;
    io->sock = ctx->sock;
    io->parent = ctx;
    io->buf.resize(65536); 

    WSABUF wsaBuf;
    wsaBuf.buf = (char*)io->buf.data();
    wsaBuf.len = (ULONG)io->buf.size();

    ctx->pending_io++;
    DWORD bytes = 0, flags = 0;
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

void WorkerPool::post_write(SocketContext* ctx, std::vector<uint8_t>&& data) {
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
        if (ctx->on_write) ctx->on_write(-1);
        delete io;
    }
}
