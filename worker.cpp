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
    SetThreadPriority(m_thread.native_handle(), THREAD_PRIORITY_ABOVE_NORMAL);

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

void Worker::post_read(SocketContext* ctx) {
    if (!ctx || ctx->read_pending) return;

    DWORD bytes = 0;
    DWORD flags = 0;
    
    memset(&ctx->read_io.overlapped, 0, sizeof(OVERLAPPED));
    ctx->read_io.type = IO_READ;

    retain_context(ctx);

    int ret = SOCKET_ERROR;

    if (ctx->is_udp) {
        ctx->wsaBuf.buf = ctx->buffer;
        ctx->wsaBuf.len = 4096;
        ctx->remote_addr_len = sizeof(ctx->remote_addr);
        
        ret = WSARecvFrom(ctx->sock, &ctx->wsaBuf, 1, &bytes, &flags, (sockaddr*)&ctx->remote_addr, &ctx->remote_addr_len, &ctx->read_io.overlapped, NULL);
    } else {
        static char dummy_buf[1];
        static WSABUF wsaBufZero = { 0, dummy_buf };
        
        ret = WSARecv(ctx->sock, &wsaBufZero, 1, &bytes, &flags, &ctx->read_io.overlapped, NULL);
    }

    if (ret == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            release_context(ctx);
        } else {
            ctx->read_pending = true;
        }
    } else {
        ctx->read_pending = true;
    }
}

void Worker::post_write(SocketContext* ctx, char* buf, int len) {
    if (!ctx || ctx->write_pending) return;

    memset(&ctx->write_io.overlapped, 0, sizeof(OVERLAPPED));
    ctx->write_io.type = IO_WRITE;
    
    ctx->wsaWriteBuf.buf = buf;
    ctx->wsaWriteBuf.len = len;

    retain_context(ctx);

    DWORD bytes = 0;
    int ret = WSASend(ctx->sock, &ctx->wsaWriteBuf, 1, &bytes, 0, &ctx->write_io.overlapped, NULL);

    if (ret == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            ctx->write_pending = false;
            release_context(ctx);
            if (ctx->on_write) ctx->on_write(-1);
        } else {
            ctx->write_pending = true;
        }
    } else {
        ctx->write_pending = true;
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
            retain_context(ctx);
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
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, on_done]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) {
            SocketContext* ctx = it->second;
            ctx->on_read = nullptr;
            ctx->on_write = nullptr;
            ctx->on_close = nullptr;
            m_sockets.erase(it);
            release_context(ctx); 
        }
        if (on_done) on_done();
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
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
        if (on_connect) {
            ctx->on_write = [on_connect](int bytes) {
                if (bytes >= 0) on_connect();
            };
        }
        
        retain_context(ctx);
        m_sockets[s] = ctx;

        CreateIoCompletionPort((HANDLE)s, m_iocp, (ULONG_PTR)ctx, 0);

        memset(&ctx->connect_io.overlapped, 0, sizeof(OVERLAPPED));
        ctx->connect_io.type = IO_CONNECT;
        
        retain_context(ctx);

        if (m_lpfnConnectEx) {
            BOOL ret = m_lpfnConnectEx(s, (sockaddr*)&addr, sizeof(addr), NULL, 0, NULL, &ctx->connect_io.overlapped);
            if (!ret && WSAGetLastError() != ERROR_IO_PENDING) {
                release_context(ctx);
            }
        } else {
             release_context(ctx);
        }
    });
    PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
}

bool Worker::send_async(SOCKET s, char* buf, int len) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_task_queue.push_back([this, s, buf, len]() {
        auto it = m_sockets.find(s);
        if (it != m_sockets.end()) {
            post_write(it->second, buf, len);
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

        BOOL ret = GetQueuedCompletionStatus(m_iocp, &bytesTransferred, &completionKey, &overlapped, 10);

        if (overlapped != NULL) {
            SocketContext* ctx = (SocketContext*)completionKey;
            IO_CONTEXT* ioCtx = (IO_CONTEXT*)overlapped;

            if (!ctx || ctx->magic != SocketContext::MAGIC_VAL) continue;

            try {
                if (ret) {
                    if (ioCtx->type == IO_READ) {
                        ctx->read_pending = false;
                        if (ctx->on_read) {
                            if (ctx->is_udp) {
                                ctx->on_read(ctx->buffer, (int)bytesTransferred, &ctx->remote_addr);
                            } else {
                                ctx->on_read(nullptr, 0, nullptr);
                            }
                        }
                        if (m_sockets.find(ctx->sock) != m_sockets.end() && !ctx->paused) {
                            post_read(ctx);
                        }
                    } else if (ioCtx->type == IO_CONNECT) {
                        setsockopt(ctx->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
                        if (ctx->on_write) ctx->on_write(0); 
                    } else if (ioCtx->type == IO_WRITE) {
                        ctx->write_pending = false;
                        if (ctx->on_write) ctx->on_write((int)bytesTransferred);
                    }
                } else {
                    if (ioCtx->type == IO_READ) {
                        ctx->read_pending = false;
                        if (ctx->on_read) ctx->on_read(nullptr, 0, nullptr);
                    } else if (ioCtx->type == IO_CONNECT) {
                        if (ctx->on_write) ctx->on_write(-1); 
                    } else if (ioCtx->type == IO_WRITE) {
                        ctx->write_pending = false;
                        if (ctx->on_write) ctx->on_write(-1); 
                    }
                }
            } catch (...) {}
            
            release_context(ctx);
        }
    }
}
