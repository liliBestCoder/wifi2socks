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

    int buf_size = 128 * 1024; // 128KB
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
        [self](char* buf, int len, sockaddr_in*) { self->on_client_initial_read(buf, len); },
        [self](int len) { self->on_write_complete(self->m_client_socket, len); },
        false
    );
}

void ProxyTCP::on_client_initial_read(char* buf, int len) {
    if (len <= 0) {
        close_session();
        return;
    }

    size_t max_buf_len = (g_config.max_sni_len > 0) ? g_config.max_sni_len : 16384;
    if (m_initial_buffer.size() + len > max_buf_len) {
        len = (int)(max_buf_len - m_initial_buffer.size());
    }
    if (len > 0) {
        m_initial_buffer.insert(m_initial_buffer.end(), (const uint8_t*)buf, (const uint8_t*)buf + len);
    }

    bool ready = false;
    if (m_initial_buffer.size() >= 5 && m_initial_buffer[0] == 0x16) { // TLS
        uint16_t tls_len = ((uint16_t)m_initial_buffer[3] << 8) | m_initial_buffer[4];
        if (m_initial_buffer.size() >= (size_t)5 + tls_len) ready = true;
    }
    else if (is_http_start(m_initial_buffer.data(), m_initial_buffer.size())) { // HTTP
        std::string host = parse_http_host(m_initial_buffer.data(), m_initial_buffer.size());
        if (!host.empty() || m_initial_buffer.size() > 1024) ready = true;
    }
    else if (m_initial_buffer.size() > 64) { // Unknown
        ready = true;
    }

    if (!ready && m_initial_buffer.size() < max_buf_len) {
        WorkerPool::instance().read_async(m_client_socket);
        return;
    }

    std::string sni = parse_tls_sni(m_initial_buffer.data(), m_initial_buffer.size());
    if (sni.empty()) sni = parse_http_host(m_initial_buffer.data(), m_initial_buffer.size());

    if (!sni.empty()) {
        m_detected_domain = sni;
        RouteAction rule = RuleManager::instance().match_domain(sni);
        if (rule == RouteAction::DIRECT) m_is_direct = true;
        else if (rule == RouteAction::PROXY) m_is_direct = false;
        else if (rule == RouteAction::BLOCK) { close_session(); return; }
        else {
            m_is_direct = GeoChecker::instance().is_cn_domain(sni);
            if (!m_is_direct) {
                if (GeoChecker::instance().is_cn_ip(ntohl(m_original_dest.ip))) m_is_direct = true;
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
    
    auto self = shared_from_this();
    WorkerPool::instance().update_read_callback(m_client_socket, [self](char* b, int l, sockaddr_in*) { self->on_client_read(b, l); });
    connect_remote();
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
    
    int buf_size = 128 * 1024;
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
    if (len <= 0) { close_session(); return; }
    m_proxy_response_buffer.insert(m_proxy_response_buffer.end(), buf, buf + len);
    const char* crlf2 = "\r\n\r\n";
    auto it = std::search(m_proxy_response_buffer.begin(), m_proxy_response_buffer.end(), crlf2, crlf2 + 4);

    if (it != m_proxy_response_buffer.end()) {
        std::string header(m_proxy_response_buffer.begin(), it + 4);
        m_proxy_response_buffer.clear();
        if (header.find(" 200 ") != std::string::npos) {
            m_state = ESTABLISHED;
            if (!m_initial_buffer.empty()) {
                auto buffer = std::make_shared<std::vector<char>>(m_initial_buffer.begin(), m_initial_buffer.end());
                {
                    std::lock_guard<std::mutex> lock(m_remote_queue_mutex);
                    m_remote_send_queue.push_back(buffer);
                    m_remote_send_queue_size += buffer->size();
                }
                m_initial_buffer.clear();
                try_send(m_remote_socket);
            }
            auto self = shared_from_this();
            WorkerPool::instance().update_read_callback(m_remote_socket, [self](char* b, int l, sockaddr_in*) { self->on_remote_read(b, l); });
            WorkerPool::instance().read_async(m_remote_socket);
        } else {
            close_session();
        }
    } else {
        WorkerPool::instance().read_async(m_remote_socket);
    }
}

void ProxyTCP::on_remote_connect() {
    int error = 0;
    int elen = sizeof(error);
    getsockopt(m_remote_socket, SOL_SOCKET, SO_ERROR, (char*)&error, &elen);
    if (error != 0) { close_session(); return; }

    if (m_is_direct) {
        m_state = ESTABLISHED;
        if (!m_initial_buffer.empty()) {
            auto buffer = std::make_shared<std::vector<char>>(m_initial_buffer.begin(), m_initial_buffer.end());
            {
                std::lock_guard<std::mutex> lock(m_remote_queue_mutex);
                m_remote_send_queue.push_back(buffer);
                m_remote_send_queue_size += buffer->size();
            }
            m_initial_buffer.clear();
            try_send(m_remote_socket);
        }
        WorkerPool::instance().read_async(m_remote_socket);
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
    if (len <= 0) { close_session(); return; }
    if (!m_client_read_paused) WorkerPool::instance().read_async(m_client_socket);
    
    if (m_state == ESTABLISHED) {
        auto buffer = std::make_shared<std::vector<char>>(buf, buf + len);
        size_t new_size;
        {
            std::lock_guard<std::mutex> lock(m_remote_queue_mutex);
            m_remote_send_queue.push_back(buffer);
            new_size = (m_remote_send_queue_size += len);
        }
        try_send(m_remote_socket);
        if (new_size > HIGH_WATER_MARK && !m_client_read_paused.exchange(true)) {
            // LOG_DEBUG("[ProxyTCP] Backpressure applied on client read.");
        }
    } else {
        m_initial_buffer.insert(m_initial_buffer.end(), (uint8_t*)buf, (uint8_t*)buf + len);
    }
}

void ProxyTCP::on_remote_read(char* buf, int len) {
    if (len <= 0) { close_session(); return; }
    if (!m_remote_read_paused) WorkerPool::instance().read_async(m_remote_socket);

    if (m_state == ESTABLISHED) {
        auto buffer = std::make_shared<std::vector<char>>(buf, buf + len);
        size_t new_size;
        {
            std::lock_guard<std::mutex> lock(m_client_queue_mutex);
            m_client_send_queue.push_back(buffer);
            new_size = (m_client_send_queue_size += len);
        }
        try_send(m_client_socket);
        if (new_size > HIGH_WATER_MARK && !m_remote_read_paused.exchange(true)) {
            // LOG_DEBUG("[ProxyTCP] Backpressure applied on remote read.");
        }
    }
}

void ProxyTCP::try_send(SOCKET socket) {
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
        if (socket == m_remote_socket) m_remote_write_in_progress = false;
        else if (socket == m_client_socket) m_client_write_in_progress = false;
        return;
    }

    auto self = shared_from_this();
    if (socket == m_remote_socket) {
        size_t new_size;
        {
            std::lock_guard<std::mutex> lock(m_remote_queue_mutex);
            if (!m_remote_send_queue.empty()) {
                auto& front_buffer = m_remote_send_queue.front();
                if (len < front_buffer->size()) {
                    front_buffer->erase(front_buffer->begin(), front_buffer->begin() + len);
                } else {
                    m_remote_send_queue.pop_front();
                }
            }
            new_size = (m_remote_send_queue_size -= len);
            m_remote_write_in_progress = false;
        }
        if (m_client_read_paused && new_size < LOW_WATER_MARK) {
            if (m_client_read_paused.exchange(false)) {
                WorkerPool::instance().read_async(m_client_socket);
            }
        }
        WorkerPool::instance().queue_task([self, socket]() { self->try_send(socket); });
    } else if (socket == m_client_socket) {
        size_t new_size;
        {
            std::lock_guard<std::mutex> lock(m_client_queue_mutex);
            if (!m_client_send_queue.empty()) {
                auto& front_buffer = m_client_send_queue.front();
                if (len < front_buffer->size()) {
                    front_buffer->erase(front_buffer->begin(), front_buffer->begin() + len);
                } else {
                    m_client_send_queue.pop_front();
                }
            }
            new_size = (m_client_send_queue_size -= len);
            m_client_write_in_progress = false;
        }
        if (m_remote_read_paused && new_size < LOW_WATER_MARK) {
            if (m_remote_read_paused.exchange(false)) {
                WorkerPool::instance().read_async(m_remote_socket);
            }
        }
        WorkerPool::instance().queue_task([self, socket]() { self->try_send(socket); });
    }
}

void ProxyTCP::close_session() {
    if (m_state.exchange(CLOSING) == CLOSING) return;
    if (m_client_socket != INVALID_SOCKET) {
        shutdown(m_client_socket, SD_BOTH);
        closesocket(m_client_socket);
        m_client_socket = INVALID_SOCKET;
    }
    if (m_remote_socket != INVALID_SOCKET) {
        shutdown(m_remote_socket, SD_BOTH);
        closesocket(m_remote_socket);
        m_remote_socket = INVALID_SOCKET;
    }
}
