#include "worker.h"
#include "logger.h"
#include "app_config.h"
#include "proxy_tcp.h"
#include <iostream>
#include <algorithm>
#include <sstream>



// --- IO_CONTEXT Pool (Thread Local to eliminate lock contention) ---
struct ThreadLocalIoPool {
    std::vector<IO_CONTEXT*> pool;
    ~ThreadLocalIoPool() {
        for (auto* io : pool) delete io;
        pool.clear();
    }
};

static thread_local ThreadLocalIoPool t_io_pool;

static bool socket_is_udp(SOCKET s, bool fallback) {
    int type = 0;
    int len = sizeof(type);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&type, &len) == 0) {
        return type == SOCK_DGRAM;
    }
    return fallback;
}

static std::string endpoint_string(SOCKET s) {
    sockaddr_in local_addr = {};
    sockaddr_in peer_addr = {};
    int local_len = sizeof(local_addr);
    int peer_len = sizeof(peer_addr);
    char local_ip[INET_ADDRSTRLEN] = "unknown";
    char peer_ip[INET_ADDRSTRLEN] = "unconnected";
    int local_port = 0;
    int peer_port = 0;
    if (getsockname(s, (sockaddr*)&local_addr, &local_len) == 0) {
        inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, sizeof(local_ip));
        local_port = ntohs(local_addr.sin_port);
    }
    if (getpeername(s, (sockaddr*)&peer_addr, &peer_len) == 0) {
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
        peer_port = ntohs(peer_addr.sin_port);
    }
    std::ostringstream os;
    os << local_ip << ":" << local_port << "->" << peer_ip << ":" << peer_port;
    return os.str();
}

IO_CONTEXT* acquire_io_context() {
    IO_CONTEXT* io = nullptr;
    if (!t_io_pool.pool.empty()) {
        io = t_io_pool.pool.back();
        t_io_pool.pool.pop_back();
    }

    if (!io) {
        return new IO_CONTEXT();
    }

    // 必须在锁外重置成员，因为清理 std::function 或 shared_ptr 可能触发析构，
    // 如果析构函数又调用了 remove_socket，会产生递归死锁。
    memset(&io->overlapped, 0, sizeof(OVERLAPPED));
    io->type = IO_READ;
    io->sock = INVALID_SOCKET;
    io->task = nullptr;
    io->parent = nullptr;
    io->data_len = 0;
    io->error_code = 0;
    memset(&io->remote_addr, 0, sizeof(io->remote_addr));
    io->remote_addr_len = 0;
    io->total_bytes_submitted = 0;
    io->write_buffers.clear();
    io->wsa_bufs.clear();
    return io;
}

void release_io_context(IO_CONTEXT* io) {
    if (!io) return;

    // 在入池前清理成员（锁外执行）
    io->task = nullptr;
    io->parent = nullptr;
    io->sock = INVALID_SOCKET;
    memset(&io->remote_addr, 0, sizeof(io->remote_addr));
    io->remote_addr_len = 0;
    io->write_buffers.clear();
    io->wsa_bufs.clear();

    if (t_io_pool.pool.size() < 1024) {
        t_io_pool.pool.push_back(io);
    }
    else {
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
        BOOL ret = GetQueuedCompletionStatus(m_iocp, &bytesTransferred, &completionKey, &overlapped, INFINITE);

        if (overlapped == NULL) {
            if (completionKey == (ULONG_PTR)this) break;
            continue;
        }

        IO_CONTEXT* io = (IO_CONTEXT*)overlapped;

        if (io->type == IO_PROXY_BUFFER) {
            auto buf = reinterpret_cast<ProxyTCP::IoBuffer*>(overlapped);
            if (buf) {
                if (buf->on_complete) {
                    int err = ret ? 0 : WSAGetLastError();
                    auto cb = std::move(buf->on_complete);
                    cb(bytesTransferred, err);
                } else {
                    delete buf;
                }
            }
            continue;
        }

        if (io->type == IO_TASK) {
            if (io->task) {
                try { io->task(); }
                catch (...) { LOG_ERROR("[Worker] Task execution failed."); }
            }
            release_io_context(io);
            continue;
        }

        if (io->type == IO_ACCEPT) {
            if (ret) {
                io->error_code = 0;
                // Success: update socket context for the new socket
                setsockopt(io->sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&io->parent->sock, sizeof(SOCKET));
                if (io->task) io->task();
            } else {
                io->error_code = WSAGetLastError();
                if (io->error_code != ERROR_OPERATION_ABORTED) {
                    LOG_ERROR("[Worker] AcceptEx failed: %d", io->error_code);
                }
                closesocket(io->sock);
                // Even on failure, we might want to notify or retry, 
                // but usually the listener will post a new AcceptEx.
                if (io->task) io->task(); 
            }
            release_io_context(io);
            continue;
        }

        if (io->type == IO_REMOVE) {
            std::shared_ptr<SocketContext> ctx = io->parent ? io->parent : WorkerPool::instance().find_context(io->sock);
            if (ctx) {
                ctx->closing = true;
                ctx->on_remove_done = io->task;
                WorkerPool::instance().unregister_context(io->sock);
                closesocket(ctx->sock);

                if (ctx.use_count() <= 2) {
                    if (ctx->on_remove_done) {
                        auto cb = std::move(ctx->on_remove_done);
                        ctx->on_remove_done = nullptr;
                        cb();
                    }
                }
            }
            else if (io->task) {
                io->task();
            }
            release_io_context(io);
            continue;
        }

        if (io->type == IO_DETACH) {
            std::shared_ptr<SocketContext> ctx = io->parent ? io->parent : WorkerPool::instance().find_context(io->sock);
            if (ctx) {
                ctx->closing = true;
                ctx->on_remove_done = io->task;
                WorkerPool::instance().unregister_context(io->sock);
                // Do NOT closesocket here.
                if (ctx.use_count() <= 2) {
                    if (ctx->on_remove_done) {
                        auto cb = std::move(ctx->on_remove_done);
                        ctx->on_remove_done = nullptr;
                        cb();
                    }
                }
            }
            else if (io->task) {
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
                    }
                    else {
                        if (ctx->on_read) ctx->on_read(nullptr, 0, nullptr);
                    }
                }
                else if (io->type == IO_WRITE) {
                    if (ctx->on_write) ctx->on_write((int)bytesTransferred, io->write_buffers);
                }
                else if (io->type == IO_CONNECT) {
                    setsockopt(ctx->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
                    if (io->task) io->task();
                    if (ctx->on_read) {
                        for (int i = 0; i < ctx->concurrent_reads; ++i) {
                            WorkerPool::instance().post_read(ctx);
                        }
                    }
                }
            }
            else {
                if (io->type == IO_READ) {
                    if (ctx->on_read) ctx->on_read(nullptr, -1, nullptr);
                }
                else if (io->type == IO_WRITE && ctx->on_write) {
                    ctx->on_write(-1, io->write_buffers);
                }
                else if (io->type == IO_CONNECT) {
                    int err = WSAGetLastError();
                    if (err == ERROR_SEM_TIMEOUT || err == WSAECONNRESET || err == WSAECONNABORTED || err == WSAETIMEDOUT || err == 10038) {
                        LOG_DEBUG("[Worker] ConnectEx async failure: %d (Normal closure)", err);
                    } else {
                        LOG_ERROR("[Worker] ConnectEx async failure: %d", err);
                    }
                    if (io->task) io->task();
                }
            }
        }

        release_io_context(io);

        if (ctx->closing && ctx.use_count() == 1) {
            if (ctx->on_remove_done) {
                auto cb = std::move(ctx->on_remove_done);
                ctx->on_remove_done = nullptr;
                cb();
            }
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

void WorkerPool::add_socket(SOCKET s, std::function<void(char*, int, sockaddr_in*)> on_read, std::function<void(int, const std::vector<std::shared_ptr<std::vector<char>>>&)> on_write, bool is_udp, std::function<void()> on_init, int concurrent_reads, const std::string& origin) {
    std::shared_ptr<SocketContext> ctx = find_context(s);
    if (ctx && ctx->closing) {
        unregister_context(s);
        ctx.reset();
    }
    if (!ctx) {
        ctx = std::make_shared<SocketContext>();
        ctx->sock = s;
        register_context(s, ctx);
        CreateIoCompletionPort((HANDLE)s, m_shared_iocp, (ULONG_PTR)ctx.get(), 0);
    }
    ctx->debug_name = (origin.empty() ? "add_socket" : origin) + std::string(" ") + endpoint_string(s);
    ctx->on_read = on_read;
    ctx->on_write = on_write;
    ctx->is_udp = socket_is_udp(s, is_udp);
    if (ctx->is_udp != is_udp) {
        LOG_WARN("[WorkerPool] corrected socket type in add_socket: requested_udp=%d actual_udp=%d sock=%llu",
            is_udp ? 1 : 0,
            ctx->is_udp ? 1 : 0,
            (unsigned long long)s);
    }
    ctx->concurrent_reads = concurrent_reads;

    if (on_init) {
        on_init();
    }

    if (on_read) {
        for (int i = 0; i < ctx->concurrent_reads; ++i) {
            post_read(ctx);
        }
    }
}

void WorkerPool::remove_socket(SOCKET s, std::function<void()> on_done) {
    IO_CONTEXT* io = acquire_io_context();
    io->type = IO_REMOVE;
    io->sock = s;
    io->task = on_done;
    auto ctx = find_context(s);
    if (ctx) {
        ctx->closing = true;
        unregister_context(s);
        io->parent = ctx;
    }
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io);
}

void WorkerPool::detach_socket(SOCKET s, std::function<void()> on_done) {
    IO_CONTEXT* io = acquire_io_context();
    io->type = IO_DETACH;
    io->sock = s;
    io->task = on_done;
    auto ctx = find_context(s);
    if (ctx) {
        ctx->closing = true;
        unregister_context(s);
        io->parent = ctx;
    }
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)io);
}

void WorkerPool::accept_async(SOCKET listen_sock, std::function<void(SOCKET, sockaddr_in&)> on_accepted) {
    std::shared_ptr<SocketContext> ctx = find_context(listen_sock);
    if (ctx && ctx->closing) {
        unregister_context(listen_sock);
        ctx.reset();
    }
    if (!ctx) {
        ctx = std::make_shared<SocketContext>();
        ctx->sock = listen_sock;
        register_context(listen_sock, ctx);
        CreateIoCompletionPort((HANDLE)listen_sock, m_shared_iocp, (ULONG_PTR)ctx.get(), 0);
    }

    IO_CONTEXT* init_task = acquire_io_context();
    init_task->type = IO_TASK;
    init_task->task = [this, listen_sock, on_accepted, ctx]() {
        LPFN_ACCEPTEX AcceptExPtr = nullptr;
        GUID guid = WSAID_ACCEPTEX;
        DWORD bytes = 0;
        WSAIoctl(listen_sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &AcceptExPtr, sizeof(AcceptExPtr), &bytes, NULL, NULL);

        if (AcceptExPtr) {
            SOCKET client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (client_socket == INVALID_SOCKET) {
                LOG_ERROR("[WorkerPool] Failed to create socket for AcceptEx.");
                return;
            }

            IO_CONTEXT* io = acquire_io_context();
            io->type = IO_ACCEPT;
            io->sock = client_socket;
            io->parent = ctx;
            io->task = [this, on_accepted, client_socket, io, listen_sock]() {
                if (io->parent && !io->parent->closing) {
                    if (io->error_code == 0) {
                        sockaddr_in remote_addr;
                        memset(&remote_addr, 0, sizeof(remote_addr));
                        
                        LPFN_GETACCEPTEXSOCKADDRS GetAcceptExSockaddrsPtr = nullptr;
                        GUID guid2 = WSAID_GETACCEPTEXSOCKADDRS;
                        DWORD bytes2 = 0;
                        WSAIoctl(client_socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid2, sizeof(guid2), &GetAcceptExSockaddrsPtr, sizeof(GetAcceptExSockaddrsPtr), &bytes2, NULL, NULL);

                        if (GetAcceptExSockaddrsPtr) {
                            LPSOCKADDR pLocalAddr = nullptr;
                            LPSOCKADDR pRemoteAddr = nullptr;
                            int local_len = 0, remote_len = 0;
                            GetAcceptExSockaddrsPtr(io->buf, 0, sizeof(sockaddr_in) + 16, sizeof(sockaddr_in) + 16, &pLocalAddr, &local_len, &pRemoteAddr, &remote_len);
                            if (pRemoteAddr && remote_len >= sizeof(sockaddr_in)) {
                                memcpy(&remote_addr, pRemoteAddr, sizeof(sockaddr_in));
                            }
                        }
                        if (on_accepted) on_accepted(client_socket, remote_addr);
                    }
                    
                    // Post next accept
                    accept_async(listen_sock, on_accepted);
                } else {
                    if (io->error_code == 0) {
                        closesocket(client_socket);
                    }
                }
            };

            BOOL ret = AcceptExPtr(listen_sock, client_socket, io->buf, 0, sizeof(sockaddr_in) + 16, sizeof(sockaddr_in) + 16, &bytes, &io->overlapped);
            if (!ret && WSAGetLastError() != ERROR_IO_PENDING) {
                closesocket(client_socket);
                release_io_context(io);
                LOG_ERROR("[WorkerPool] AcceptEx failed immediately: %d", WSAGetLastError());
            }
        } else {
            LOG_ERROR("[WorkerPool] Failed to get AcceptEx pointer.");
        }
    };
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)init_task);
}

void WorkerPool::connect_async(SOCKET s, sockaddr_in addr, std::function<void()> on_connect,
    std::function<void(char*, int, sockaddr_in*)> on_read,
    std::function<void(int, const std::vector<std::shared_ptr<std::vector<char>>>&)> on_write,
    std::function<void()> on_init) {
    
    struct sockaddr_in bindAddr;
    memset(&bindAddr, 0, sizeof(bindAddr));
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = INADDR_ANY;
    bindAddr.sin_port = 0;
    bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr));

    std::shared_ptr<SocketContext> ctx = find_context(s);
    if (ctx && ctx->closing) {
        unregister_context(s);
        ctx.reset();
    }
    if (!ctx) {
        ctx = std::make_shared<SocketContext>();
        ctx->sock = s;
        register_context(s, ctx);
        CreateIoCompletionPort((HANDLE)s, m_shared_iocp, (ULONG_PTR)ctx.get(), 0);
    }
    ctx->debug_name = std::string("connect_async ") + endpoint_string(s);
    ctx->on_read = on_read;
    ctx->on_write = on_write;
    ctx->is_udp = socket_is_udp(s, false);
    if (ctx->is_udp) {
        LOG_WARN("[WorkerPool] connect_async received UDP socket unexpectedly: sock=%llu",
            (unsigned long long)s);
    }
    ctx->concurrent_reads = CONCURRENT_READ_COUNT;

    if (on_init) {
        on_init();
    }

    IO_CONTEXT* init_task = acquire_io_context();
    init_task->type = IO_TASK;
    init_task->task = [this, s, addr, on_connect, ctx]() {
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
        }
        else {
            LOG_ERROR("[WorkerPool] Failed to get ConnectEx pointer.");
        }
    };
    PostQueuedCompletionStatus(m_shared_iocp, 0, 0, (LPOVERLAPPED)init_task);
}

bool WorkerPool::sendto_async(SOCKET s, const uint8_t* data, size_t len, const sockaddr_in& to) {
    if (len == 0) return true;
    auto ctx = find_context(s);
    if (ctx && !ctx->closing) {
        ctx->is_udp = socket_is_udp(ctx->sock, ctx->is_udp);
        size_t remaining = len;
        size_t offset = 0;

        while (remaining > 0) {
            IO_CONTEXT* io = acquire_io_context();
            io->type = IO_WRITE;
            io->sock = ctx->sock;
            io->parent = ctx;

            size_t chunk = (std::min)(remaining, sizeof(io->buf));
            memcpy(io->buf, data + offset, chunk);
            io->data_len = chunk;
            io->total_bytes_submitted = chunk;
            io->remote_addr = to;
            io->remote_addr_len = sizeof(to);

            WSABUF w;
            w.buf = (char*)io->buf;
            w.len = (ULONG)io->data_len;
            io->wsa_bufs.push_back(w);

            DWORD bytes = 0;
            int ret = WSASendTo(ctx->sock, io->wsa_bufs.data(), (DWORD)io->wsa_bufs.size(), &bytes, 0, (const sockaddr*)&io->remote_addr, io->remote_addr_len, &io->overlapped, NULL);

            if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
                LOG_ERROR("[WorkerPool] WSASendTo chunk failed: %d", WSAGetLastError());
                if (ctx->on_write) ctx->on_write(-1, io->write_buffers);
                release_io_context(io);
                return false;
            }

            remaining -= chunk;
            offset += chunk;
        }
        return true;
    }
    return false;
}

bool WorkerPool::send_async(SOCKET s, const uint8_t* data, size_t len) {
    if (len == 0) return true;
    auto ctx = find_context(s);
    if (ctx && !ctx->closing) {
        ctx->is_udp = socket_is_udp(ctx->sock, ctx->is_udp);
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
        ctx->is_udp = socket_is_udp(ctx->sock, ctx->is_udp);
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
        ctx->is_udp = socket_is_udp(ctx->sock, ctx->is_udp);
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
    }
    else {
        ret = WSARecv(ctx->sock, io->wsa_bufs.data(), 1, &bytes, &flags, &io->overlapped, NULL);
    }

    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        int err = WSAGetLastError();
        LOG_ERROR("[WorkerPool] %s post_read failed: err=%d sock=%llu",
            ctx->is_udp ? "UDP" : "TCP",
            err,
            (unsigned long long)ctx->sock);
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
    io->total_bytes_submitted = 0;

    io->wsa_bufs.reserve(io->write_buffers.size());
    for (auto& buf : io->write_buffers) {
        WSABUF w;
        w.buf = buf->data();
        w.len = (ULONG)buf->size();
        io->wsa_bufs.push_back(w);
        io->total_bytes_submitted += w.len;
    }

    DWORD bytes = 0;
    int ret = WSASend(ctx->sock, io->wsa_bufs.data(), (DWORD)io->wsa_bufs.size(), &bytes, 0, &io->overlapped, NULL);

    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        LOG_ERROR("[WorkerPool] WSASend failed: %d", WSAGetLastError());
        if (ctx->on_write) ctx->on_write(-1, io->write_buffers);
        release_io_context(io);
    }
}


void WorkerPool::post_write(const std::shared_ptr<SocketContext>& ctx, const uint8_t* data, size_t len) {
    if (!ctx || ctx->closing || len == 0) return;

    size_t remaining = len;
    size_t offset = 0;

    while (remaining > 0) {
        IO_CONTEXT* io = acquire_io_context();
        io->type = IO_WRITE;
        io->sock = ctx->sock;
        io->parent = ctx;

        size_t chunk = (std::min)(remaining, sizeof(io->buf));
        memcpy(io->buf, data + offset, chunk);
        io->data_len = chunk;
        io->total_bytes_submitted = chunk;

        WSABUF w;
        w.buf = (char*)io->buf;
        w.len = (ULONG)io->data_len;
        io->wsa_bufs.push_back(w);

        DWORD bytes = 0;
        int ret = WSASend(ctx->sock, io->wsa_bufs.data(), 1, &bytes, 0, &io->overlapped, NULL);

        if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
            int err = WSAGetLastError();
            sockaddr_in local_addr = {};
            sockaddr_in peer_addr = {};
            int local_len = sizeof(local_addr);
            int peer_len = sizeof(peer_addr);
            char local_ip[INET_ADDRSTRLEN] = "unknown";
            char peer_ip[INET_ADDRSTRLEN] = "unknown";
            int local_port = 0;
            int peer_port = 0;
            bool actual_udp = socket_is_udp(ctx->sock, ctx->is_udp);
            if (getsockname(ctx->sock, (sockaddr*)&local_addr, &local_len) == 0) {
                inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, sizeof(local_ip));
                local_port = ntohs(local_addr.sin_port);
            }
            if (getpeername(ctx->sock, (sockaddr*)&peer_addr, &peer_len) == 0) {
                inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
                peer_port = ntohs(peer_addr.sin_port);
            }
            LOG_ERROR("[WorkerPool] WSASend chunk failed: err=%d sock=%llu udp=%d actual_udp=%d local=%s:%d peer=%s:%d len=%zu origin=%s",
                err, (unsigned long long)ctx->sock, ctx->is_udp ? 1 : 0, actual_udp ? 1 : 0, local_ip, local_port, peer_ip, peer_port, chunk,
                ctx->debug_name.c_str());
            if (ctx->on_write) ctx->on_write(-1, io->write_buffers);
            release_io_context(io);
            break;
        }

        remaining -= chunk;
        offset += chunk;
    }
}

