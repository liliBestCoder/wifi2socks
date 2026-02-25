#include "proxy_tcp.h"
#include "logger.h"
#include "app_config.h"
#include "tls_parser.h"
#include "rule_manager.h"
#include "geo_checker.h"
#include <WS2tcpip.h>
#include <algorithm>

static const size_t TCP_BUFFER_SIZE = 32768; // 32KB

// Helpers for buffer management
ProxyTCP::IoBuffer* ProxyTCP::alloc_buffer(size_t size) {
    // Allocate a dedicated buffer for TCP stream
    IoBuffer* buf = new IoBuffer();
    buf->buffer = new char[TCP_BUFFER_SIZE];
    buf->capacity = TCP_BUFFER_SIZE;
    buf->owner = this;
    
    // Default to empty read buffer
    buf->total_bytes = 0;
    buf->written_bytes = 0;
    buf->wsa_buf.buf = buf->buffer; 
    buf->wsa_buf.len = (ULONG)TCP_BUFFER_SIZE;
    
    return buf;
}

void ProxyTCP::free_buffer(IoBuffer* buffer) {
    if (!buffer) return;
    if (buffer->buffer) {
        delete[] buffer->buffer;
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
    m_client_pending_read_count = 0;
    m_remote_pending_read_count = 0;
}

ProxyTCP::~ProxyTCP() {
    close_session();
}

void ProxyTCP::start() {
    // Don't connect immediately. Wait for first packet to decide routing.
    // Register client socket with WorkerPool to manage IOCP association and lifecycle
    WorkerPool::instance().add_socket(m_client_socket, nullptr, nullptr);

    // Initial reads on client
    post_reads(m_client_socket);
}

void ProxyTCP::connect_remote() {
    m_state = CONNECTING;

    sockaddr_in remote_addr = { 0 };
    remote_addr.sin_family = AF_INET;

    unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
    char ip_str[INET_ADDRSTRLEN];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

    if (m_is_direct) {
        LOG_INFO("[TCP] Routing DIRECT for %s (IP: %s)", m_detected_domain.empty() ? "(IP)" : m_detected_domain.c_str(), ip_str);
        remote_addr.sin_addr.s_addr = m_original_dest.ip;
        remote_addr.sin_port = m_original_dest.port;
    }
    else {
        LOG_INFO("[TCP] Routing PROXY for %s (IP: %s)", m_detected_domain.empty() ? "(Domain unknown)" : m_detected_domain.c_str(), ip_str);
        inet_pton(AF_INET, g_config.upstream_ip.c_str(), &remote_addr.sin_addr);
        remote_addr.sin_port = htons(g_config.upstream_port);
    }

    m_remote_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_remote_socket == INVALID_SOCKET) {
        LOG_ERROR("[ProxyTCP] Failed to create remote socket");
        close_session();
        return;
    }

    // Use WorkerPool to handle the ConnectEx logic
    auto self = shared_from_this();
    if (m_is_direct) {
        WorkerPool::instance().connect_async(
            m_remote_socket,
            remote_addr,
            [self]() { self->on_remote_connect(); },
            nullptr, nullptr
        );
    } else {
        WorkerPool::instance().connect_async(
            m_remote_socket,
            remote_addr,
            [self]() { self->on_remote_connect(); },
            nullptr, nullptr
        );
    }
}

void ProxyTCP::on_remote_connect() {
    if (m_state == CLOSING) return;
    
    // Check socket error
    int error = 0;
    int elen = sizeof(error);
    getsockopt(m_remote_socket, SOL_SOCKET, SO_ERROR, (char*)&error, &elen);
    if (error != 0) {
        LOG_ERROR("[ProxyTCP] Connect failed with error: %d", error);
        close_session();
        return;
    }

    if (m_is_direct) {
        m_state = ESTABLISHED;
        // Start reading from remote
        post_reads(m_remote_socket);
        // Flush any queued writes
        std::lock_guard<std::mutex> lock(m_mutex);
        process_write_queue(m_remote_socket);
    } else {
        m_state = AWAITING_CONNECT_RESPONSE;
        
        // Send HTTP CONNECT
        std::string target_host = m_detected_domain;
        if (target_host.empty()) {
            unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
            char ip_str[INET_ADDRSTRLEN];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            target_host = ip_str;
        }
        uint16_t target_port = ntohs(m_original_dest.port);
        std::string connect_req = "CONNECT " + target_host + ":" + std::to_string(target_port) + " HTTP/1.1\r\nHost: " + target_host + ":" + std::to_string(target_port) + "\r\n\r\n";

        WorkerPool::instance().send_async(m_remote_socket, (const uint8_t*)connect_req.data(), connect_req.length());
        
        // Start reading response
        post_reads(m_remote_socket);
    }
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
        buffer->wsa_buf.buf = buffer->buffer;
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
    // Concurrency control using Atomic Counter (No locking needed for check/increment usually, 
    // but WSARecv needs safe socket access or we assume single-thread dispatcher for post?
    // Worker thread calls this. Multiple worker threads might call for different sockets.
    // Same socket is usually serialized by IOCP but post_reads might be called from multiple places?
    // We are safe: Atomic int handles the count.
    
    if (m_state == CLOSING) return;

    std::atomic<int>* pending_count = (socket == m_client_socket) ? &m_client_pending_read_count : &m_remote_pending_read_count;
    bool paused = (socket == m_client_socket) ? m_client_read_paused : m_remote_read_paused;

    if (paused) return;

    // Loop to keep pipeline full
    while (pending_count->load() < MAX_PENDING_READS) {
        IoBuffer* buf = alloc_buffer();
        if (!buf) break; 

        buf->op = IoBuffer::READ;
        buf->socket = socket;
        
        // Optimistically increment before IO to reserve slot
        (*pending_count)++; 

        DWORD flags = 0;
        int ret = WSARecv(socket, &buf->wsa_buf, 1, NULL, &flags, &buf->overlapped, NULL);
        
        if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
            LOG_ERROR("[ProxyTCP] WSARecv failed: %d", WSAGetLastError());
            (*pending_count)--; // Revert
            free_buffer(buf);
            close_session();
            break; 
        }
    }
}

void ProxyTCP::handle_client_read_complete(IoBuffer* buffer) {
    // Decrement pending count (slot available)
    m_client_pending_read_count--;

    // Logic for SNI/Host parsing and Hooking
    const uint8_t* buf_data = (const uint8_t*)buffer->buffer;
    size_t buf_size = buffer->total_bytes;

    if (m_state == INITIAL) {
        m_initial_buffer.insert(m_initial_buffer.end(), buf_data, buf_data + buf_size);
        
        const auto* combined_data = m_initial_buffer.data();
        const auto combined_size = m_initial_buffer.size();

        // Hook for any HTTP request to the gateway on port 80
        in_addr gateway_addr_struct{};
        if (inet_pton(AF_INET, g_config.gateway_ip.c_str(), &gateway_addr_struct) == 1 &&
            m_original_dest.ip == gateway_addr_struct.s_addr && ntohs(m_original_dest.port) == 80) {
            
            std::string_view payload((const char*)combined_data, combined_size);
            if (payload.find("GET ") == 0 || payload.find("POST ") == 0 || payload.find("HEAD ") == 0 || payload.find("OPTIONS ") == 0) {
                LOG_INFO("[TCP] Hooking HTTP request to gateway on port 80. Returning 204.");
                const char* response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                send(m_client_socket, response, (int)strlen(response), 0);
                close_session();
                free_buffer(buffer);
                return;
            }
        }

        // Check for /generate_204 hook
        if (ntohs(m_original_dest.port) == 80 && is_generate_204_request(combined_data, combined_size)) {
             LOG_INFO("[TCP] Hooking /generate_204 request.");
             const char* response = "HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
             send(m_client_socket, response, (int)strlen(response), 0);
             close_session();
             free_buffer(buffer);
             return;
        }

        std::string sni = parse_tls_sni(combined_data, combined_size);
        bool proceed = false;
        
        if (!sni.empty()) {
            m_detected_domain = sni;
            proceed = true;
        } else {
            std::string host = parse_http_host(combined_data, combined_size);
            if (!host.empty()) {
                m_detected_domain = host; 
                proceed = true;
            } else if (combined_size >= 4096) {
                proceed = true; // Give up
            }
        }

        if (proceed) {
            // Routing Logic
            if (!m_detected_domain.empty()) {
                RouteAction rule = RuleManager::instance().match_domain(m_detected_domain);
                if (rule == RouteAction::DIRECT) m_is_direct = true;
                else if (rule == RouteAction::PROXY) m_is_direct = false;
                else if (rule == RouteAction::BLOCK) { 
                    LOG_INFO("[TCP] Blocking domain: %s", m_detected_domain.c_str());
                    close_session(); 
                    free_buffer(buffer);
                    return; 
                }
                else {
                    m_is_direct = GeoChecker::instance().is_cn_domain(m_detected_domain);
                    if (!m_is_direct && GeoChecker::instance().is_cn_ip(ntohl(m_original_dest.ip))) {
                        m_is_direct = true;
                    }
                }
            } else {
                uint32_t ip_h = ntohl(m_original_dest.ip);
                RouteAction rule = RuleManager::instance().match_ip(ip_h);
                if (GeoChecker::is_private_ip(ip_h) || rule == RouteAction::DIRECT) m_is_direct = true;
                else if (rule == RouteAction::PROXY) m_is_direct = false;
                else if (rule == RouteAction::BLOCK) { 
                    LOG_INFO("[TCP] Blocking IP: %s", m_detected_domain.c_str());
                    close_session(); 
                    free_buffer(buffer);
                    return; 
                }
                else { m_is_direct = GeoChecker::instance().is_cn_ip(ip_h); }
            }
            
            // Clear sniffing buffer
            m_initial_buffer.clear();
            
            // Connect
            connect_remote();
        }
    }

    queue_write(m_remote_socket, buffer);
    post_reads(m_client_socket);
}

void ProxyTCP::handle_remote_read_complete(IoBuffer* buffer) {
    m_remote_pending_read_count--;

    // Handle Proxy Response if waiting
    if (m_state == AWAITING_CONNECT_RESPONSE) {
        m_proxy_response_buffer.insert(m_proxy_response_buffer.end(), buffer->buffer, buffer->buffer + buffer->total_bytes);
        const char* crlf2 = "\r\n\r\n";
        auto it = std::search(m_proxy_response_buffer.begin(), m_proxy_response_buffer.end(), crlf2, crlf2 + 4);

        if (it != m_proxy_response_buffer.end()) {
            std::string header(m_proxy_response_buffer.begin(), it + 4);
            // Check for 200 Connection Established
            if (header.find(" 200 ") != std::string::npos) {
                m_state = ESTABLISHED;
                m_proxy_response_buffer.clear();
                
                size_t header_len = std::distance(m_proxy_response_buffer.begin(), it) + 4;
                size_t data_len_in_packet = buffer->total_bytes;
                
                if (data_len_in_packet > header_len) {
                    // Adjust buffer to point after header
                    buffer->wsa_buf.buf += header_len;
                    buffer->wsa_buf.len -= (ULONG)header_len;
                    buffer->total_bytes -= header_len;
                    
                    queue_write(m_client_socket, buffer);
                } else {
                    // Just header, nothing to forward to client
                    free_buffer(buffer);
                }
                
                // Flush queued writes to remote (data from client that was waiting)
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    process_write_queue(m_remote_socket);
                }
            } else {
                LOG_ERROR("[ProxyTCP] Proxy refused connection: %s", header.c_str());
                close_session();
                free_buffer(buffer);
            }
        } else {
            // Header not complete yet, wait for more?
            free_buffer(buffer);
        }
        
        post_reads(m_remote_socket);
        return;
    }

    queue_write(m_client_socket, buffer);
    post_reads(m_remote_socket);
}

void ProxyTCP::queue_write(SOCKET dest_socket, IoBuffer* buffer) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    buffer->op = IoBuffer::WRITE;
    buffer->socket = dest_socket;
    
    // Setup WSABUF for writing
    buffer->wsa_buf.buf = buffer->buffer;
    buffer->wsa_buf.len = (ULONG)buffer->total_bytes;

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
    
    if (socket == m_remote_socket && m_state != ESTABLISHED) {
        return;
    }

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

        m_client_write_queue_size -= buffer->total_bytes; 
        
        if (buffer->written_bytes < buffer->total_bytes) {
             // Partial write
             buffer->wsa_buf.buf += buffer->written_bytes; 
             buffer->wsa_buf.len -= (ULONG)buffer->written_bytes;
             buffer->total_bytes -= buffer->written_bytes; 
             buffer->written_bytes = 0; 

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
    if (m_state == CLOSING) return;
    m_state = CLOSING;

    if (m_client_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_client_socket);
        m_client_socket = INVALID_SOCKET;
    }
    if (m_remote_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_remote_socket);
        m_remote_socket = INVALID_SOCKET;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    // Only clean write queues. Pending reads are handled by OS cancellation -> on_io_complete -> free_buffer.
    auto clean_queue = [this](std::deque<IoBuffer*>& q) {
        for (auto* buf : q) free_buffer(buf);
        q.clear();
    };

    clean_queue(m_client_write_queue);
    clean_queue(m_remote_write_queue);
    clean_queue(m_client_inflight_writes);
    clean_queue(m_remote_inflight_writes);
}