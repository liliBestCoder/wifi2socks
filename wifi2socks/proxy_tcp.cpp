#include "proxy_tcp.h"
#include "logger.h"
#include "app_config.h"
#include <WS2tcpip.h>
#include <algorithm>

// Helpers for buffer management
ProxyTCP::IoBuffer* ProxyTCP::alloc_buffer(size_t size) {
    auto* packet = PacketPool::instance().alloc(size);
    if (!packet) return nullptr;

    IoBuffer* buf = new IoBuffer();
    buf->packet = packet;
    buf->capacity = packet->capacity;
    buf->owner = this;
    
    // Default to empty read buffer
    buf->total_bytes = 0;
    buf->written_bytes = 0;
    buf->wsa_buf.buf = (char*)packet->data; // Cast to char* for WSABUF
    buf->wsa_buf.len = (ULONG)packet->capacity;
    
    return buf;
}

void ProxyTCP::free_buffer(IoBuffer* buffer) {
    if (!buffer) return;
    if (buffer->packet) {
        PacketPool::instance().free(buffer->packet);
    }
    delete buffer;
}

ProxyTCP::ProxyTCP(SOCKET client_socket, OriginalDestination dest)
    : m_client_socket(client_socket), m_remote_socket(INVALID_SOCKET), 
      m_original_dest(dest), m_state(INITIAL), m_is_direct(false) {
    
    m_client_read_paused = false;
    m_remote_read_paused = false;
    m_client_write_queue_size = 0;
    m_remote_write_queue_size = 0;
}

ProxyTCP::~ProxyTCP() {
    close_session();
}

void ProxyTCP::start() {
    m_state = CONNECTING;
    
    // Register client socket with WorkerPool to manage IOCP association and lifecycle
    WorkerPool::instance().add_socket(m_client_socket, nullptr, nullptr);

    // Initial reads on client
    post_reads(m_client_socket);
    
    // Connect to remote
    connect_remote();
}

void ProxyTCP::connect_remote() {
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = m_original_dest.ip;
    addr.sin_port = m_original_dest.port;

    m_remote_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_remote_socket == INVALID_SOCKET) {
        LOG_ERROR("[ProxyTCP] Failed to create remote socket");
        close_session();
        return;
    }

    // Use WorkerPool to handle the ConnectEx logic
    WorkerPool::instance().connect_async(
        m_remote_socket,
        addr,
        [this_ptr = shared_from_this()]() {
            this_ptr->on_remote_connect();
        },
        nullptr, nullptr
    );
}

void ProxyTCP::on_remote_connect() {
    if (m_state == CLOSING) return;
    
    m_state = ESTABLISHED;
    post_reads(m_remote_socket);
}

void ProxyTCP::on_io_complete(IoBuffer* buffer, DWORD bytes_transferred, int error) {
    // If closing, just clean up
    if (m_state == CLOSING) {
        free_buffer(buffer);
        return;
    }

    // Check for errors or EOF on Read
    if (error != 0 || (bytes_transferred == 0 && buffer->op == IoBuffer::READ)) {
        free_buffer(buffer);
        close_session();
        return;
    }

    if (buffer->op == IoBuffer::READ) {
        buffer->total_bytes = bytes_transferred;
        // Reset wsa_buf for writing (pointer at start, len = data read)
        buffer->wsa_buf.buf = (char*)buffer->packet->data;
        buffer->wsa_buf.len = (ULONG)buffer->total_bytes;
        
        if (buffer->socket == m_client_socket) {
            handle_client_read_complete(buffer);
        } else {
            handle_remote_read_complete(buffer);
        }
    } else { // WRITE
        buffer->written_bytes += bytes_transferred;
        
        if (buffer->socket == m_client_socket) {
            handle_client_write_complete(buffer);
        } else {
            handle_remote_write_complete(buffer);
        }
    }
}

void ProxyTCP::post_reads(SOCKET socket) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state == CLOSING) return;

    std::deque<IoBuffer*>* pending_reads = (socket == m_client_socket) ? &m_client_pending_reads : &m_remote_pending_reads;
    bool paused = (socket == m_client_socket) ? m_client_read_paused : m_remote_read_paused;

    if (paused) return;

    while (pending_reads->size() < MAX_PENDING_READS) {
        IoBuffer* buf = alloc_buffer();
        if (!buf) break; 

        buf->op = IoBuffer::READ;
        buf->socket = socket;
        
        DWORD flags = 0;
        int ret = WSARecv(socket, &buf->wsa_buf, 1, NULL, &flags, &buf->overlapped, NULL);
        
        if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
            LOG_ERROR("[ProxyTCP] WSARecv failed: %d", WSAGetLastError());
            free_buffer(buf);
            // We can't easily call close_session() here if we already hold lock (if close_session takes lock)
            // But post_reads takes lock.
            // Let's schedule close via worker or just set state?
            // Since we are in the thread of execution, setting state might be enough to stop future ops.
            // But we need to ensure sockets are closed.
            // We'll release lock and call close_session?
            // Danger of re-entrancy.
            // For now, let's assume one failure stops the flow and eventually cleanup happens.
            // Or better:
            break; 
        }
        
        pending_reads->push_back(buf);
    }
}

void ProxyTCP::handle_client_read_complete(IoBuffer* buffer) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find(m_client_pending_reads.begin(), m_client_pending_reads.end(), buffer);
        if (it != m_client_pending_reads.end()) {
            m_client_pending_reads.erase(it);
        }
    }

    queue_write(m_remote_socket, buffer);
    post_reads(m_client_socket);
}

void ProxyTCP::handle_remote_read_complete(IoBuffer* buffer) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find(m_remote_pending_reads.begin(), m_remote_pending_reads.end(), buffer);
        if (it != m_remote_pending_reads.end()) {
            m_remote_pending_reads.erase(it);
        }
    }

    queue_write(m_client_socket, buffer);
    post_reads(m_remote_socket);
}

void ProxyTCP::queue_write(SOCKET dest_socket, IoBuffer* buffer) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    buffer->op = IoBuffer::WRITE;
    buffer->socket = dest_socket;
    // buffer->written_bytes = 0; // Already 0 from init, or updated if partial retry (logic below handles new buffers)
    // Actually handle_client_read_complete passes a FRESHLY read buffer, so written_bytes is 0.
    
    std::deque<IoBuffer*>* q;
    size_t* q_size;
    bool* pause_flag_ptr;

    if (dest_socket == m_client_socket) {
        q = &m_client_write_queue;
        q_size = &m_client_write_queue_size;
        pause_flag_ptr = &m_remote_read_paused;
    } else {
        q = &m_remote_write_queue;
        q_size = &m_remote_write_queue_size;
        pause_flag_ptr = &m_client_read_paused;
    }

    q->push_back(buffer);
    *q_size += buffer->total_bytes;

    if (*q_size >= HIGH_WATER_MARK && !(*pause_flag_ptr)) {
        *pause_flag_ptr = true;
    }

    process_write_queue(dest_socket);
}

void ProxyTCP::process_write_queue(SOCKET socket) {
    // Expects m_mutex to be HELD
    
    std::deque<IoBuffer*>* queue;
    std::deque<IoBuffer*>* inflight;
    
    if (socket == m_client_socket) {
        queue = &m_client_write_queue;
        inflight = &m_client_inflight_writes;
    } else {
        queue = &m_remote_write_queue;
        inflight = &m_remote_inflight_writes;
    }

    while (!queue->empty() && inflight->size() < MAX_PENDING_WRITES) {
        IoBuffer* buf = queue->front();
        queue->pop_front();
        
        memset(&buf->overlapped, 0, sizeof(OVERLAPPED));
        
        int ret = WSASend(socket, &buf->wsa_buf, 1, NULL, 0, &buf->overlapped, NULL);
        
        if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
            LOG_ERROR("[ProxyTCP] WSASend failed: %d", WSAGetLastError());
            free_buffer(buf);
            // Don't break immediately, maybe try next? 
            // If socket is dead, next will fail too.
            // For safety, stop submitting.
            break;
        }
        
        inflight->push_back(buf);
    }
}

void ProxyTCP::handle_client_write_complete(IoBuffer* buffer) {
    bool need_resume_remote = false;
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = std::find(m_client_inflight_writes.begin(), m_client_inflight_writes.end(), buffer);
        if (it != m_client_inflight_writes.end()) {
            m_client_inflight_writes.erase(it);
        }

        // Deduct submitted bytes (we added total_bytes to queue_size when queuing)
        // We should deduct when we finish writing.
        m_client_write_queue_size -= buffer->total_bytes; 
        
        if (buffer->written_bytes < buffer->total_bytes) {
             // Partial write
             buffer->wsa_buf.buf += buffer->written_bytes; // Advance pointer
             buffer->wsa_buf.len -= (ULONG)buffer->written_bytes;
             buffer->total_bytes -= buffer->written_bytes; // Remaining bytes
             buffer->written_bytes = 0; // Reset for next op

             // Re-add remaining bytes to size
             m_client_write_queue_size += buffer->total_bytes;
             
             m_client_write_queue.push_front(buffer);
        } else {
             free_buffer(buffer);
        }

        if (m_client_write_queue_size < LOW_WATER_MARK && m_remote_read_paused) {
            m_remote_read_paused = false;
            need_resume_remote = true;
        }
        
        process_write_queue(m_client_socket);
    }
    
    if (need_resume_remote) {
        post_reads(m_remote_socket);
    }
}

void ProxyTCP::handle_remote_write_complete(IoBuffer* buffer) {
    bool need_resume_client = false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = std::find(m_remote_inflight_writes.begin(), m_remote_inflight_writes.end(), buffer);
        if (it != m_remote_inflight_writes.end()) {
            m_remote_inflight_writes.erase(it);
        }

        m_remote_write_queue_size -= buffer->total_bytes;

        if (buffer->written_bytes < buffer->total_bytes) {
             buffer->wsa_buf.buf += buffer->written_bytes;
             buffer->wsa_buf.len -= (ULONG)buffer->written_bytes;
             buffer->total_bytes -= buffer->written_bytes;
             buffer->written_bytes = 0;
             
             m_remote_write_queue_size += buffer->total_bytes;
             m_remote_write_queue.push_front(buffer);
        } else {
             free_buffer(buffer);
        }

        if (m_remote_write_queue_size < LOW_WATER_MARK && m_client_read_paused) {
            m_client_read_paused = false;
            need_resume_client = true;
        }

        process_write_queue(m_remote_socket);
    }

    if (need_resume_client) {
        post_reads(m_client_socket);
    }
}

void ProxyTCP::close_session() {
    State expected = ESTABLISHED;
    // Simple state check. Note: State transition might need stronger sync if called from multiple threads,
    // but close_session is usually triggered once on error.
    if (m_state == CLOSING) return;
    m_state = CLOSING;

    // Remove sockets from WorkerPool (closes them)
    // We don't hold lock here to avoid deadlock if remove_socket calls back? 
    // remove_socket is async usually.
    if (m_client_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_client_socket);
        m_client_socket = INVALID_SOCKET;
    }
    if (m_remote_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_remote_socket);
        m_remote_socket = INVALID_SOCKET;
    }

    // Now clean up queues
    std::lock_guard<std::mutex> lock(m_mutex);

    auto clean_queue = [this](std::deque<IoBuffer*>& q) {
        for (auto* buf : q) free_buffer(buf);
        q.clear();
    };

    clean_queue(m_client_pending_reads);
    clean_queue(m_remote_pending_reads);
    clean_queue(m_client_write_queue);
    clean_queue(m_remote_write_queue);
    clean_queue(m_client_inflight_writes);
    clean_queue(m_remote_inflight_writes);
}
