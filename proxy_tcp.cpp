#include "proxy_tcp.h"
#include "logger.h"
#include "app_config.h"
#include "tls_parser.h"
#include "rule_manager.h"
#include "geo_checker.h"
#include <WS2tcpip.h>
#include <mstcpip.h>
#include <algorithm>

// --- IoBuffer Pool for high performance ---
static std::mutex g_proxy_buf_mtx;
static ProxyTCP::IoBuffer* g_proxy_buf_stack[2048]; // Use a fixed-size stack for faster access
static int g_proxy_buf_top = 0;

ProxyTCP::IoBuffer* ProxyTCP::alloc_buffer(size_t size) {
    ProxyTCP::IoBuffer* buf = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_proxy_buf_mtx);
        if (g_proxy_buf_top > 0) {
            buf = g_proxy_buf_stack[--g_proxy_buf_top];
        }
    }

    if (!buf) {
        buf = new IoBuffer();
    }

    // Reset buffer state for reuse (minimal reset)
    memset(&buf->overlapped, 0, sizeof(OVERLAPPED));
    buf->on_complete = nullptr;
    buf->next_in_batch = nullptr;
    buf->total_bytes = 0;
    buf->written_bytes = 0;
    buf->state = IoBuffer::IO_READING;
    buf->flags = 0;
    buf->wsa_buf.buf = (char*)buf->buffer;
    buf->wsa_buf.len = (ULONG)sizeof(buf->buffer);

    return buf;
}

void ProxyTCP::free_buffer(IoBuffer* buffer) {
    if (!buffer) return;
    
    buffer->on_complete = nullptr;

    std::lock_guard<std::mutex> lock(g_proxy_buf_mtx);
    if (g_proxy_buf_top < 2048) {
        g_proxy_buf_stack[g_proxy_buf_top++] = buffer;
    } else {
        delete buffer;
    }
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
    m_client_inflight_write_count = 0;
    m_remote_inflight_write_count = 0;

    m_client_eof = false;
    m_remote_eof = false;
    m_client_fin_sent = false;
    m_remote_fin_sent = false;
    m_last_access_time = GetTickCount64();

    if (m_client_socket != INVALID_SOCKET) {
        enable_keepalive(m_client_socket);
    }
}

ProxyTCP::~ProxyTCP() {
    close_session();
}

void ProxyTCP::start() {
    auto self = shared_from_this();

    {
        std::lock_guard<std::mutex> lock(g_sessions_mtx);
        g_sessions.push_back(self);
    }

    WorkerPool::instance().add_socket(m_client_socket, nullptr, nullptr, false, [this, self]() {
        post_reads(m_client_socket);
    });
}

void ProxyTCP::connect_remote() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state != INITIAL) return;
        m_state = CONNECTING;
    }

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

    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &remote_addr.sin_addr, target_ip, INET_ADDRSTRLEN);
    LOG_DEBUG("[ProxyTCP] Connecting to %s:%d (DIRECT=%d, Domain=%s)", 
        target_ip, ntohs(remote_addr.sin_port), m_is_direct, m_detected_domain.c_str());

    // 优化 socket 性能
    int optval = 1;
    setsockopt(m_remote_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&optval, sizeof(optval)); // 禁用 Nagle 算法
    enable_keepalive(m_remote_socket);

    auto self = shared_from_this();
    WorkerPool::instance().connect_async(
        m_remote_socket,
        remote_addr,
        [self]() { self->on_remote_connect(); },
        nullptr, nullptr
    );
}

void ProxyTCP::on_remote_connect() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state == CLOSING) return;

        int error = 0;
        int elen = sizeof(error);
        getsockopt(m_remote_socket, SOL_SOCKET, SO_ERROR, (char*)&error, &elen);
        if (error != 0) {
            LOG_DEBUG("[ProxyTCP] Connect failed with error: %d", error);
            close_session_internal();
            return;
        }

        if (m_is_direct) {
            m_state = ESTABLISHED;
        }
        else {
            m_state = AWAITING_CONNECT_RESPONSE;
        }
    }

    if (m_is_direct) {
        post_reads(m_remote_socket);
        std::lock_guard<std::mutex> lock(m_mutex);
        process_write_queue(m_remote_socket);
    }
    else {
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
        post_reads(m_remote_socket);
    }
}

void ProxyTCP::on_io_complete(IoBuffer* buffer, DWORD bytes_transferred, int error) {
    if (m_state == CLOSING) {
        free_buffer(buffer);
        return;
    }

    // Handle READ completion
    if (buffer->state == IoBuffer::IO_READING) {
        if (error != 0 || bytes_transferred == 0) {
            // EOF or Error
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (buffer->socket == m_client_socket) {
                    m_client_pending_read_count--;
                }
                else {
                    m_remote_pending_read_count--;
                }

                if (error == 0) {
                    // Graceful FIN: Mark as EOF in queue to preserve order
                    buffer->state = IoBuffer::IO_EOF;
                } else {
                    // Actual error: Drop and close immediately
                    buffer->state = IoBuffer::IO_DROPPED;
                    
                    if (error == ERROR_NETNAME_DELETED || error == ERROR_CONNECTION_ABORTED || error == 10038 ||
                        error == 10054 || error == 10053 || error == 10060 || error == 10057 || error == 121 || 
                        error == 1236 || error == 64) {
                        LOG_DEBUG("[TCP] IO closure on socket: %d", error);
                    } else {
                        LOG_ERROR("[TCP] IO Error on socket: %d", error);
                    }
                    close_session_internal();
                }
                process_write_queue(m_client_socket);
                process_write_queue(m_remote_socket);
            }
            return;
        }

        buffer->total_bytes = bytes_transferred;
        m_last_access_time = GetTickCount64();
        if (buffer->socket == m_client_socket) {
            handle_client_read_complete(buffer);
        }
        else {
            handle_remote_read_complete(buffer);
        }
    }
    // Handle WRITE completion
    else if (buffer->state == IoBuffer::IO_WRITING) {
        if (error != 0) {
            IoBuffer* b = buffer;
            while (b) {
                IoBuffer* next = b->next_in_batch;
                free_buffer(b);
                b = next;
            }
            if (error != 10038) close_session();
            return;
        }

        // --- Correctly handle Gather Write completion to prevent data reordering ---
        std::vector<IoBuffer*> unfinished;
        DWORD remaining = bytes_transferred;
        IoBuffer* current = buffer;

        while (current) {
            IoBuffer* next = current->next_in_batch;
            current->next_in_batch = nullptr;

            DWORD contributed = (DWORD)(current->total_bytes - current->written_bytes);
            if (remaining >= contributed) {
                current->written_bytes = current->total_bytes;
                remaining -= contributed;
                
                // Buffer fully sent: regular completion path
                if (current->socket == m_client_socket) handle_client_write_complete(current);
                else handle_remote_write_complete(current);
            }
            else {
                current->written_bytes += remaining;
                remaining = 0;
                // Buffer not fully sent: needs re-queuing
                unfinished.push_back(current);
            }
            current = next;
        }

        if (!unfinished.empty()) {
            std::lock_guard<std::mutex> lock(m_mutex);
            SOCKET s = unfinished[0]->socket;
            auto& q = (s == m_client_socket) ? m_client_write_queue : m_remote_write_queue;
            auto& q_size = (s == m_client_socket) ? m_client_write_queue_size : m_remote_write_queue_size;

            // Push back to front in reverse order to maintain original stream sequence
            for (int i = (int)unfinished.size() - 1; i >= 0; --i) {
                IoBuffer* b = unfinished[i];
                b->state = IoBuffer::IO_READY;
                q_size += (b->total_bytes - b->written_bytes);
                q.push_front(b);
            }
            process_write_queue(s);
        }
    }
}

void ProxyTCP::post_reads(SOCKET socket) {
    if (socket == INVALID_SOCKET) return;

    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_state == CLOSING) return;

    std::atomic<int>* pending_count = (socket == m_client_socket) ? &m_client_pending_read_count : &m_remote_pending_read_count;
    bool paused = (socket == m_client_socket) ? m_client_read_paused : m_remote_read_paused;
    bool eof = (socket == m_client_socket) ? m_client_eof.load() : m_remote_eof.load();

    if (paused || eof) return;

    std::deque<IoBuffer*>* dest_queue = (socket == m_client_socket) ? &m_remote_write_queue : &m_client_write_queue;
    auto self = shared_from_this();

    while (pending_count->load() < MAX_PENDING_READS) {
        if (m_state == CLOSING) break;

        IoBuffer* buf = alloc_buffer();
        if (!buf) break;

        buf->state = IoBuffer::IO_READING;
        buf->socket = socket;
        buf->on_complete = [this, self, buf](DWORD bytes, int err) {
            this->on_io_complete(buf, bytes, err);
        };
        (*pending_count)++;

        dest_queue->push_back(buf);

        DWORD bytes = 0;
        buf->flags = 0; // Reset flags for each call
        int ret = WSARecv(socket, &buf->wsa_buf, 1, &bytes, &buf->flags, &buf->overlapped, NULL);

        if (ret == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                if (err != 10038 && err != 10054 && err != 10053 && err != 10060 && err != 10057) {
                    LOG_ERROR("[ProxyTCP] WSARecv failed: %d", err);
                } else {
                    LOG_DEBUG("[ProxyTCP] WSARecv failed (err: %d, state: %d), closing session", err, (int)m_state.load());
                }
                (*pending_count)--;
                if (!dest_queue->empty() && dest_queue->back() == buf) dest_queue->pop_back();
                free_buffer(buf);
                
                // Unlock before calling close_session to avoid deadlocks
                lock.unlock();
                if (err != 10038) close_session();
                return;
            }
        }
    }
}

void ProxyTCP::handle_client_read_complete(IoBuffer* buffer) {
    bool should_connect = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_client_pending_read_count--;

        if (m_state == INITIAL) {
            const uint8_t* buf_data = (const uint8_t*)buffer->buffer;
            size_t buf_size = buffer->total_bytes;
            m_initial_buffer.insert(m_initial_buffer.end(), buf_data, buf_data + buf_size);

            const auto* combined_data = m_initial_buffer.data();
            const auto combined_size = m_initial_buffer.size();

            std::string sni = parse_tls_sni(combined_data, combined_size);
            bool proceed = false;
            if (!sni.empty()) {
                m_detected_domain = sni;
                proceed = true;
            }
            else {
                std::string host = parse_http_host(combined_data, combined_size);
                if (!host.empty()) {
                    m_detected_domain = host;
                    proceed = true;
                }
                else if (combined_size >= 512) {
                    proceed = true;
                }
            }

            if (proceed) {
                if (!m_detected_domain.empty()) {
                    RouteAction rule = RuleManager::instance().match_domain(m_detected_domain);
                    if (rule == RouteAction::DIRECT) m_is_direct = true;
                    else if (rule == RouteAction::PROXY) m_is_direct = false;
                    else if (rule == RouteAction::BLOCK) {
                        LOG_INFO("[TCP] Blocking domain: %s", m_detected_domain.c_str());
                        buffer->state = IoBuffer::IO_DROPPED;
                        close_session_internal(); return;
                    }
                    else {
                        m_is_direct = GeoChecker::instance().is_cn_domain(m_detected_domain);
                        if (!m_is_direct && GeoChecker::instance().is_cn_ip(ntohl(m_original_dest.ip))) m_is_direct = true;
                    }
                }
                else {
                    uint32_t ip_h = ntohl(m_original_dest.ip);
                    RouteAction rule = RuleManager::instance().match_ip(ip_h);
                    if (GeoChecker::is_private_ip(ip_h) || rule == RouteAction::DIRECT) m_is_direct = true;
                    else if (rule == RouteAction::PROXY) m_is_direct = false;
                    else if (rule == RouteAction::BLOCK) {
                        LOG_INFO("[TCP] Blocking IP: %s", m_detected_domain.c_str());
                        buffer->state = IoBuffer::IO_DROPPED;
                        close_session_internal(); return;
                    }
                    else { m_is_direct = GeoChecker::instance().is_cn_ip(ip_h); }
                }
                m_initial_buffer.clear();
                should_connect = true;
            }
        }

        if (buffer->state != IoBuffer::IO_DROPPED) {
            buffer->state = IoBuffer::IO_READY;
            m_remote_write_queue_size += buffer->total_bytes;
            if (m_remote_write_queue_size >= HIGH_WATER_MARK) m_client_read_paused = true;
            process_write_queue(m_remote_socket);
        }
        else {
            process_write_queue(m_remote_socket);
        }
    }

    if (should_connect) {
        connect_remote();
    }
    post_reads(m_client_socket);
}

void ProxyTCP::handle_remote_read_complete(IoBuffer* buffer) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_remote_pending_read_count--;

        bool is_handshake_response = false;
        if (m_state == AWAITING_CONNECT_RESPONSE) {
            m_proxy_response_buffer.insert(m_proxy_response_buffer.end(), buffer->buffer, buffer->buffer + buffer->total_bytes);
            const char* crlf2 = "\r\n\r\n";
            auto it = std::search(m_proxy_response_buffer.begin(), m_proxy_response_buffer.end(), crlf2, crlf2 + 4);

            if (it != m_proxy_response_buffer.end()) {
                std::string header(m_proxy_response_buffer.begin(), it + 4);
                if (header.find(" 200 ") != std::string::npos) {
                    m_state = ESTABLISHED;
                    size_t header_len = std::distance(m_proxy_response_buffer.begin(), it) + 4;
                    m_proxy_response_buffer.clear();

                    if (buffer->total_bytes > header_len) {
                        buffer->total_bytes -= header_len;
                        // Move remaining data to front of buffer
                        memmove(buffer->buffer, buffer->buffer + header_len, buffer->total_bytes);
                    }
                    else {
                        is_handshake_response = true;
                    }

                    process_write_queue(m_remote_socket);
                }
                else {
                    LOG_ERROR("[ProxyTCP] Proxy refused connection: %s", header.c_str());
                    buffer->state = IoBuffer::IO_DROPPED;
                    close_session_internal(); return;
                }
            }
            else {
                is_handshake_response = true;
            }
        }

        if (is_handshake_response) {
            buffer->state = IoBuffer::IO_DROPPED;
        }
        else {
            buffer->state = IoBuffer::IO_READY;
            m_client_write_queue_size += buffer->total_bytes;
            if (m_client_write_queue_size >= HIGH_WATER_MARK) m_remote_read_paused = true;
        }
        process_write_queue(m_client_socket);
    }
    post_reads(m_remote_socket);
}

void ProxyTCP::process_write_queue(SOCKET socket) {
    if (m_state == CLOSING) return;

    if (socket != INVALID_SOCKET) {
        // Remote write requires connection to be established
        if (socket == m_remote_socket && m_state != ESTABLISHED) return;

        std::deque<IoBuffer*>* queue = (socket == m_client_socket) ? &m_client_write_queue : &m_remote_write_queue;
        std::atomic<int>* inflight_count = (socket == m_client_socket) ? &m_client_inflight_write_count : &m_remote_inflight_write_count;

        while (!queue->empty() && inflight_count->load() < MAX_PENDING_WRITES) {
            if (m_state == CLOSING) break;

            IoBuffer* leader = queue->front();

            // If the head is still READING, we must wait to maintain stream order
            if (leader->state == IoBuffer::IO_READING) break;

            queue->pop_front();
            if (leader->state == IoBuffer::IO_DROPPED) {
                free_buffer(leader);
                continue;
            }

            if (leader->state == IoBuffer::IO_EOF) {
                // EOF reached the front of the queue: Set flags in correct order
                if (socket == m_client_socket) {
                    if (!m_remote_eof) {
                        m_remote_eof = true;
                        LOG_DEBUG("[TCP] Remote EOF reached queue head");
                    }
                }
                else {
                    if (!m_client_eof) {
                        m_client_eof = true;
                        LOG_DEBUG("[TCP] Client EOF reached queue head");
                    }
                }
                free_buffer(leader);
                continue;
            }

            if (leader->state == IoBuffer::IO_READY) {
                // --- IMPLEMENT GATHER WRITE (BATCHING) ---
                WSABUF batch_bufs[MAX_GATHER_BATCH];
                batch_bufs[0].buf = (char*)leader->buffer + leader->written_bytes;
                batch_bufs[0].len = (ULONG)(leader->total_bytes - leader->written_bytes);

                IoBuffer* current = leader;
                int count = 1;

                // Gather more ready buffers from queue
                while (count < MAX_GATHER_BATCH && !queue->empty()) {
                    IoBuffer* next = queue->front();
                    if (next->state != IoBuffer::IO_READY) break;

                    queue->pop_front();
                    next->state = IoBuffer::IO_WRITING;
                    current->next_in_batch = next;
                    current = next;

                    batch_bufs[count].buf = (char*)next->buffer + next->written_bytes;
                    batch_bufs[count].len = (ULONG)(next->total_bytes - next->written_bytes);
                    count++;
                }

                leader->state = IoBuffer::IO_WRITING;
                leader->socket = socket;
                memset(&leader->overlapped, 0, sizeof(OVERLAPPED));

                auto self = shared_from_this();
                leader->on_complete = [this, self, leader](DWORD bytes, int err) {
                    this->on_io_complete(leader, bytes, err);
                };

                DWORD bytes_sent = 0;
                (*inflight_count)++;
                int ret = WSASend(socket, batch_bufs, count, &bytes_sent, 0, &leader->overlapped, NULL);
                if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
                    int err = WSAGetLastError();
                    if (err == 10054 || err == 10053 || err == 10060 || err == 10057 || err == 10038) {
                        LOG_DEBUG("[ProxyTCP] Send failed (err: %d), closing session", err);
                    }
                    else {
                        LOG_ERROR("[ProxyTCP] WSASend Gather failed: %d", err);
                    }
                    (*inflight_count)--;
                    IoBuffer* b = leader;
                    while (b) {
                        IoBuffer* n = b->next_in_batch;
                        free_buffer(b);
                        b = n;
                    }
                    close_session_internal(); break;
                }
            }
            else {
                break;
            }
        }

        // After attempting to drain queue, check if we need to send FIN
        bool is_eof = (socket == m_client_socket) ? m_remote_eof.load() : m_client_eof.load();
        std::atomic<bool>* fin_sent = (socket == m_client_socket) ? &m_client_fin_sent : &m_remote_fin_sent;

        if (is_eof && queue->empty() && inflight_count->load() == 0 && !fin_sent->load()) {
            *fin_sent = true;
            LOG_DEBUG("[TCP] Shutdown send on socket %p", (void*)socket);
            shutdown(socket, SD_SEND);
        }
    }

    // Final Closure Logic with Timeout Safeguards: 
    uint64_t now = GetTickCount64();
    uint64_t idle_time = now - m_last_access_time.load();

    // A session is only truly done when:
    // 1. Client has sent EOF AND Proxy has sent FIN to Client.
    // 2. Remote has sent EOF AND Proxy has sent FIN to Remote.
    bool fully_closed = (m_client_eof && m_client_fin_sent && m_remote_eof && m_remote_fin_sent);

    // Safeguard 1: If any side has started closing, don't wait forever for the other side (30s max)
    bool partial_close_timeout = (m_client_fin_sent || m_remote_fin_sent || m_client_eof || m_remote_eof) &&
        (idle_time > FIN_WAIT_TIMEOUT_MS);

    // Safeguard 2: Absolute idle timeout
    bool absolute_idle_timeout = (idle_time > IDLE_TIMEOUT_MS);

    if (fully_closed || partial_close_timeout || absolute_idle_timeout) {
        if (partial_close_timeout) LOG_DEBUG("[TCP] Closing due to FIN_WAIT timeout.");
        else if (absolute_idle_timeout) LOG_DEBUG("[TCP] Closing due to absolute idle timeout.");
        else LOG_DEBUG("[TCP] Both sides gracefully closed. Cleaning up.");

        close_session_internal();
    }
}

void ProxyTCP::handle_client_write_complete(IoBuffer* buffer) {
    bool need_resume_remote = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_client_inflight_write_count--;
        m_client_write_queue_size -= buffer->total_bytes;

        buffer->state = IoBuffer::IO_COMPLETED;
        m_last_access_time = GetTickCount64();
        free_buffer(buffer);

        if (m_client_write_queue_size < LOW_WATER_MARK && m_remote_read_paused) {
            m_remote_read_paused = false;
            need_resume_remote = true;
        }
        process_write_queue(m_client_socket);
    }
    if (need_resume_remote) post_reads(m_remote_socket);
}

void ProxyTCP::handle_remote_write_complete(IoBuffer* buffer) {
    bool need_resume_client = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_remote_inflight_write_count--;
        m_remote_write_queue_size -= buffer->total_bytes;

        buffer->state = IoBuffer::IO_COMPLETED;
        m_last_access_time = GetTickCount64();
        free_buffer(buffer);

        if (m_remote_write_queue_size < LOW_WATER_MARK && m_client_read_paused) {
            m_client_read_paused = false;
            need_resume_client = true;
        }
        process_write_queue(m_remote_socket);
    }
    if (need_resume_client) post_reads(m_client_socket);
}

void ProxyTCP::close_session() {
    std::lock_guard<std::mutex> lock(m_mutex);
    close_session_internal();
}

void ProxyTCP::close_session_internal() {
    if (m_state == CLOSING) return;
    
    unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
    LOG_DEBUG("[TCP] Closing session for %s (IP: %d.%d.%d.%d:%d), state: %d", 
        m_detected_domain.empty() ? "(unknown)" : m_detected_domain.c_str(),
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], ntohs(m_original_dest.port),
        (int)m_state.load());

    m_state = CLOSING;

    if (m_client_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_client_socket);
        m_client_socket = INVALID_SOCKET;
    }
    if (m_remote_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_remote_socket);
        m_remote_socket = INVALID_SOCKET;
    }

    auto clean_safe = [this](std::deque<IoBuffer*>& q) {
        for (auto* buf : q) {
            if (buf->state == IoBuffer::IO_READY || buf->state == IoBuffer::IO_DROPPED || buf->state == IoBuffer::IO_EOF) free_buffer(buf);
        }
        q.clear();
        };
    clean_safe(m_client_write_queue);
    clean_safe(m_remote_write_queue);
}

void ProxyTCP::check_all_timeouts() {
    std::vector<std::shared_ptr<ProxyTCP>> sessions_to_check;
    {
        std::lock_guard<std::mutex> lock(g_sessions_mtx);
        for (auto it = g_sessions.begin(); it != g_sessions.end(); ) {
            if (auto s = it->lock()) {
                sessions_to_check.push_back(s);
                ++it;
            } else {
                it = g_sessions.erase(it);
            }
        }
    }

    for (auto& s : sessions_to_check) {
        std::lock_guard<std::mutex> lock(s->m_mutex);
        // Trigger timeout and closure checks for both directions
        s->process_write_queue(s->m_client_socket);
        s->process_write_queue(s->m_remote_socket);
    }
}
