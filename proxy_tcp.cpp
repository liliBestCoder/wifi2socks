#include "proxy_tcp.h"
#include "logger.h"
#include "app_config.h"
#include "rule_manager.h"
#include "tls_parser.h"
#include "geo_checker.h"
#include "main_dispatcher.h"
#include "traffic_manager.h"

#include <mswsock.h>
#include <vector>
#include <algorithm>

ProxyTCP::ProxyTCP(SOCKET client_socket, OriginalDestination dest)
    : m_state(INITIAL),
      m_client_socket(client_socket),
      m_remote_socket(INVALID_SOCKET),
      m_original_dest(dest),
      m_is_direct(false)
{
    u_long mode = 1;
    ioctlsocket(m_client_socket, FIONBIO, &mode);

    int buf_size = 1024 * 1024; // 128KB
    setsockopt(m_client_socket, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
    setsockopt(m_client_socket, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));

    BOOL nodelay = TRUE;
    setsockopt(m_client_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));
}

ProxyTCP::~ProxyTCP() {
}

void ProxyTCP::start() {
    auto self = shared_from_this();
    WorkerPool::instance().add_socket(
        m_client_socket,
        [self](char* buf, int len, sockaddr_in*) { self->on_client_read(buf, len); },
        [self](int len) { self->on_write_complete(self->m_client_socket, len); },
        false
    );
}



void ProxyTCP::connect_remote() {
    m_state = CONNECTING;
    auto self = shared_from_this();
    sockaddr_in remote_addr = {0};
    remote_addr.sin_family = AF_INET;

    unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
    char ip_str[INET_ADDRSTRLEN];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

    if (m_is_direct) {
        LOG_INFO("[ProxyTCP] Routing DIRECT for %s (IP: %s)", m_detected_domain.empty() ? "(IP)" : m_detected_domain.c_str(), ip_str);
        remote_addr.sin_addr.s_addr = m_original_dest.ip;
        remote_addr.sin_port = m_original_dest.port;
    } else {
        LOG_INFO("[ProxyTCP] Routing PROXY for %s (IP: %s)", m_detected_domain.empty() ? "(Domain unknown)" : m_detected_domain.c_str(), ip_str);
        inet_pton(AF_INET, g_config.proxy_ip.c_str(), &remote_addr.sin_addr);
        remote_addr.sin_port = htons(g_config.proxy_port);
    }
    
    m_remote_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(m_remote_socket == INVALID_SOCKET) { close_session(); return; }
    
    int buf_size = 1024 * 1024;
    setsockopt(m_remote_socket, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
    setsockopt(m_remote_socket, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));
    BOOL nodelay = TRUE;
    setsockopt(m_remote_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));
    u_long mode = 1;
    ioctlsocket(m_remote_socket, FIONBIO, &mode);
    
    auto on_read_handler = [self](char* b, int l, sockaddr_in*) { self->on_remote_read(b, l); };
    auto on_write_handler = [self](int len) { self->on_write_complete(self->m_remote_socket, len); };
    
    if (m_is_direct) {
        WorkerPool::instance().connect_async(m_remote_socket, remote_addr, [self]() { self->on_remote_connect(); }, on_read_handler, on_write_handler);
    } else {
        WorkerPool::instance().connect_async(m_remote_socket, remote_addr, [self]() { self->on_remote_connect(); }, [self](char* b, int l, sockaddr_in*) { self->on_proxy_connect_response(b, l); }, on_write_handler);
    }
}

void ProxyTCP::on_proxy_connect_response(char* buf, int len) {
    if (m_state == ESTABLISHED) {
        on_remote_read(buf, len);
        WorkerPool::instance().read_async(m_remote_socket);
        return;
    }

    if (len <= 0) { close_session(); return; }
    m_proxy_response_buffer.insert(m_proxy_response_buffer.end(), buf, buf + len);
    const char* crlf2 = "\r\n\r\n";
    auto it = std::search(m_proxy_response_buffer.begin(), m_proxy_response_buffer.end(), crlf2, crlf2 + 4);

    if (it != m_proxy_response_buffer.end()) {
        std::string header(m_proxy_response_buffer.begin(), it + 4);
        m_proxy_response_buffer.clear();
        if (header.find(" 200 ") != std::string::npos) {
            m_state = ESTABLISHED;
            // Connection is established. Try to send any buffered data.
            try_send(m_remote_socket);
        } else {
            close_session();
        }
    }

    WorkerPool::instance().read_async(m_remote_socket);
}

void ProxyTCP::on_remote_connect() {
    int error = 0;
    int elen = sizeof(error);
    getsockopt(m_remote_socket, SOL_SOCKET, SO_ERROR, (char*)&error, &elen);
    if (error != 0) { 
        close_session(); 
        return; 
    }

    if (m_is_direct) {
        m_state = ESTABLISHED;
        try_send(m_remote_socket);
    } else {
        m_state = AWAITING_CONNECT_RESPONSE;
        std::string target_host = m_detected_domain;
        if (target_host.empty()) {
            unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
            char ip_str[INET_ADDRSTRLEN];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            target_host = ip_str;
        }
        uint16_t target_port = ntohs(m_original_dest.port);
        std::string connect_req = "CONNECT " + target_host + ":" + std::to_string(target_port) + " HTTP/1.1\r\nHost: " + target_host + ":" + std::to_string(target_port) + "\r\n\r\n";
        
        // Use raw pointer send_async for simple string
        WorkerPool::instance().send_async(m_remote_socket, (const uint8_t*)connect_req.data(), connect_req.length());
    }
}

void ProxyTCP::on_client_read(char* buf, int len) {
    if (len <= 0) {
        m_client_at_eof = true;
        if (m_remote_send_queue_size == 0) {
            close_session();
        }
        return;
    }

    // --- Dual-Write Logic ---
    // 1. Always write to the main queue for eventual forwarding.
    auto buffer_for_queue = std::make_shared<std::vector<char>>(buf, buf + len);
    {
        std::lock_guard<std::mutex> lock(m_remote_queue_mutex);
        m_remote_send_queue.push_back(buffer_for_queue);
        m_remote_send_queue_size += len;
    }

    // 2. In INITIAL state, also write to the contiguous buffer for parsing (no lock needed).
    if (m_state == INITIAL) {
        m_initial_buffer.insert(m_initial_buffer.end(), (const uint8_t*)buf, (const uint8_t*)buf + len);
    }
    // --- End of Dual-Write ---


    // --- State Machine ---
    if (m_state == INITIAL) {
        const auto* buf_data = m_initial_buffer.data();
        const auto buf_size = m_initial_buffer.size();

        // Check for /generate_204 hook on port 80
        if (ntohs(m_original_dest.port) == 80 && is_generate_204_request(buf_data, buf_size)) {
            unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
            char ip_str[INET_ADDRSTRLEN];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            LOG_INFO("[ProxyTCP] Hooking /generate_204 request on port 80 to %s from client", ip_str);
            const char* response = "HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            WorkerPool::instance().send_async(m_client_socket, (const uint8_t*)response, (int)strlen(response));
            close_session();
            return;
        }

        std::string sni;
        bool proceed = false;

        // Per user's suggestion, the lock is removed as this is single-threaded.
        // Also, cache data and size to avoid repeated calls.
        sni = parse_tls_sni(buf_data, buf_size);
        if (!sni.empty()) {
            proceed = true;
        }
        else {
            std::string host = parse_http_host(buf_data, buf_size);
            if (!host.empty()) {
                sni = host;
                proceed = true;
            }
            // If we still can't determine the domain, check if we have received too much data.
            else if (buf_size >= 4096) {
                proceed = true; // Give up parsing and proceed with IP-based routing.
            }
        }


        if (proceed) {
            // Routing
            if (!sni.empty()) {
                m_detected_domain = sni;
                RouteAction rule = RuleManager::instance().match_domain(sni);
                if (rule == RouteAction::DIRECT) m_is_direct = true;
                else if (rule == RouteAction::PROXY) m_is_direct = false;
                else if (rule == RouteAction::BLOCK) { close_session(); return; }
                else {
                    m_is_direct = GeoChecker::instance().is_cn_domain(sni);
                    if (!m_is_direct && GeoChecker::instance().is_cn_ip(ntohl(m_original_dest.ip))) {
                        m_is_direct = true;
                    }
                }
            } else {
                uint32_t ip_h = ntohl(m_original_dest.ip);
                RouteAction rule = RuleManager::instance().match_ip(ip_h);
                if (GeoChecker::is_private_ip(ip_h) || rule == RouteAction::DIRECT) m_is_direct = true;
                else if (rule == RouteAction::PROXY) m_is_direct = false;
                else if (rule == RouteAction::BLOCK) { close_session(); return; }
                else { m_is_direct = GeoChecker::instance().is_cn_ip(ip_h); }
            }
            
            // "Burn after reading": Clear the initial buffer (no lock needed).
            m_initial_buffer.clear();

            // Change state and connect.
            m_state = CONNECTING;
            connect_remote();
        }
        // If not enough data and not proceeding, just wait for the next read event.
    }
    else if (m_state == ESTABLISHED) {
        try_send(m_remote_socket);
    } 
    // For CONNECTING or AWAITING_PROXY_RESPONSE, we just buffer. Data is already in the queue.

    // Continue the read loop unconditionally.
    WorkerPool::instance().read_async(m_client_socket);
}

void ProxyTCP::on_remote_read(char* buf, int len) {
    if (len <= 0) {
        m_remote_at_eof = true;
        if (m_client_send_queue_size == 0) {
            close_session();
        }
        return;
    }

    if (m_state == ESTABLISHED) {
        auto buffer = std::make_shared<std::vector<char>>(buf, buf + len);
        {
            std::lock_guard<std::mutex> lock(m_client_queue_mutex);
            m_client_send_queue.push_back(buffer);
            m_client_send_queue_size += len;
        }
        LOG_INFO("domain:%s start forward to client", m_detected_domain.c_str());
        try_send(m_client_socket);
    }

    // Continue the read loop unconditionally.
    WorkerPool::instance().read_async(m_remote_socket);
}

void ProxyTCP::try_send(SOCKET socket) {
    if (m_state == CLOSING) return;
    if (socket == m_remote_socket) {
        std::lock_guard<std::mutex> lock(m_remote_queue_mutex);
        if (m_remote_write_in_progress || m_remote_send_queue.empty()) return;
        m_remote_write_in_progress = true;
        WorkerPool::instance().send_async(m_remote_socket, m_remote_send_queue.front());
    } else if (socket == m_client_socket) {
        std::lock_guard<std::mutex> lock(m_client_queue_mutex);
        if (m_client_write_in_progress || m_client_send_queue.empty()) return;
        m_client_write_in_progress = true;
        WorkerPool::instance().send_async(m_client_socket, m_client_send_queue.front());
    }
}

void ProxyTCP::on_write_complete(SOCKET socket, int len) {
    if (len <= 0) {
        close_session();
        return;
    }

    auto self = shared_from_this();
    if (socket == m_remote_socket) {
        if (m_state != ESTABLISHED) return;

        {
            std::lock_guard<std::mutex> lock(m_remote_queue_mutex);
            if (!m_remote_write_in_progress) return; // Ignore manual writes (like CONNECT req)

            if (!m_remote_send_queue.empty()) {
                auto& front_buffer = m_remote_send_queue.front();
                if (len < front_buffer->size()) {
                    front_buffer->erase(front_buffer->begin(), front_buffer->begin() + len);
                } else {
                    m_remote_send_queue.pop_front();
                }
            }
            m_remote_send_queue_size -= len;
            m_remote_write_in_progress = false;

            if (m_client_at_eof && m_remote_send_queue_size == 0) {
                close_session();
                return;
            }
        }
        WorkerPool::instance().queue_task([self, socket]() { self->try_send(socket); });
    } else if (socket == m_client_socket) {
        if (m_state != ESTABLISHED) return;

        {
            std::lock_guard<std::mutex> lock(m_client_queue_mutex);
            if (!m_client_write_in_progress) return; // Ignore manual writes (like 204 hook)

            if (!m_client_send_queue.empty()) {
                auto& front_buffer = m_client_send_queue.front();
                if (len < front_buffer->size()) {
                    front_buffer->erase(front_buffer->begin(), front_buffer->begin() + len);
                } else {
                    m_client_send_queue.pop_front();
                }
            }
            m_client_send_queue_size -= len;
            m_client_write_in_progress = false;

            if (m_remote_at_eof && m_client_send_queue_size == 0) {
                close_session();
                return;
            }
        }
        WorkerPool::instance().queue_task([self, socket]() { self->try_send(socket); });
    }
}

void ProxyTCP::close_session() {
    if (m_state.exchange(CLOSING) == CLOSING) return;
    if (m_client_socket != INVALID_SOCKET) {
        shutdown(m_client_socket, SD_BOTH);
        WorkerPool::instance().remove_socket(m_client_socket);
        m_client_socket = INVALID_SOCKET;
    }
    if (m_remote_socket != INVALID_SOCKET) {
        shutdown(m_remote_socket, SD_BOTH);
        WorkerPool::instance().remove_socket(m_remote_socket);
        m_remote_socket = INVALID_SOCKET;
    }
}
