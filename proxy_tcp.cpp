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

bool is_generate_204_request(const uint8_t* data, size_t len) {
    if (len < 20) return false;
    return (memcmp(data, "GET /generate_204", 17) == 0);
}

ProxyTCP::ProxyTCP(SOCKET client_socket, OriginalDestination dest)
    : m_state(INITIAL),
      m_client_socket(client_socket),
      m_remote_socket(INVALID_SOCKET),
      m_original_dest(dest),
      m_is_direct(false)
{
    u_long mode = 1;
    ioctlsocket(m_client_socket, FIONBIO, &mode);

    int buf_size = 64 * 1024; // 64KB
    setsockopt(m_client_socket, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
    setsockopt(m_client_socket, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));

    BOOL nodelay = TRUE;
    setsockopt(m_client_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));
}

ProxyTCP::~ProxyTCP() {
    if (m_client_socket != INVALID_SOCKET) {
        closesocket(m_client_socket);
    }
    if (m_remote_socket != INVALID_SOCKET) {
        closesocket(m_remote_socket);
    }
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

    // --- 1. Check for generate_204 ---
    if (ntohs(m_original_dest.port) == 80) {
        if (is_generate_204_request(m_initial_buffer.data(), m_initial_buffer.size())) {
            LOG_INFO("[ProxyTCP] Intercepted /generate_204. Sending mock response.");
            const char* resp204 = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
            send(m_client_socket, resp204, (int)strlen(resp204), 0);
            close_session();
            return;
        } else if (m_initial_buffer.size() < 17 && memcmp(m_initial_buffer.data(), "GET /generate_204", m_initial_buffer.size()) == 0) {
            return; // Wait for more to confirm
        }
    }

    // --- 2. Protocol Readiness Check (borrowed from user suggestion) ---
    bool ready = false;
    if (m_initial_buffer.size() >= 5 && m_initial_buffer[0] == 0x16) {
        // TLS: Check if we have the full ClientHello record
        uint16_t tls_len = ((uint16_t)m_initial_buffer[3] << 8) | m_initial_buffer[4];
        if (m_initial_buffer.size() >= (size_t)5 + tls_len) ready = true;
    }
    else if (is_http_start(m_initial_buffer.data(), m_initial_buffer.size())) {
        // HTTP: Wait for Host header or 1KB
        std::string host = parse_http_host(m_initial_buffer.data(), m_initial_buffer.size());
        if (!host.empty() || m_initial_buffer.size() > 1024) ready = true;
    }
    else if (m_initial_buffer.size() > 64) {
        // Unknown protocol: Decide after 64 bytes
        ready = true;
    }

    if (!ready && m_initial_buffer.size() < max_buf_len) {
        return; // Continue buffering
    }

    // --- 3. Parsing and Routing Decision ---
    std::string sni = parse_tls_sni(m_initial_buffer.data(), m_initial_buffer.size());
    if (sni.empty()) sni = parse_http_host(m_initial_buffer.data(), m_initial_buffer.size());

    if (!sni.empty()) {
        m_detected_domain = sni;
        RouteAction rule = RuleManager::instance().match_domain(sni);
        if (rule == RouteAction::DIRECT) m_is_direct = true;
        else if (rule == RouteAction::PROXY) m_is_direct = false;
        else if (rule == RouteAction::BLOCK) {
            LOG_INFO("[ProxyTCP] Domain %s blocked by rule.", sni.c_str());
            close_session();
            return;
        }
        else {
            // PASS: Check GeoIP and special domains
            m_is_direct = GeoChecker::instance().is_cn_domain(sni) || 
                          GeoChecker::instance().is_tencent_domain(sni);
            
            // Fallback: If domain check is not sure, check destination IP
            if (!m_is_direct) {
                uint32_t ip_h = ntohl(m_original_dest.ip);
                if (GeoChecker::instance().is_cn_ip(ip_h)) {
                    m_is_direct = true;
                }
            }
        }
    } else {
        uint32_t ip_h = ntohl(m_original_dest.ip);
        RouteAction rule = RuleManager::instance().match_ip(ip_h);
        
        if (GeoChecker::is_private_ip(ip_h) || rule == RouteAction::DIRECT) {
            m_is_direct = true;
        } else if (rule == RouteAction::PROXY) {
            m_is_direct = false;
        } else if (rule == RouteAction::BLOCK) {
            char ip_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &m_original_dest.ip, ip_buf, INET_ADDRSTRLEN);
            LOG_INFO("[ProxyTCP] IP %s blocked by rule.", ip_buf);
            close_session();
            return;
        } else {
            m_is_direct = GeoChecker::instance().is_cn_ip(ip_h);
        }
    }
    
    auto self = shared_from_this();
    WorkerPool::instance().update_read_callback(m_client_socket, [self](char* b, int l, sockaddr_in*) { self->on_client_read(b, l); });
    
    connect_remote();
}

void ProxyTCP::connect_remote() {
    m_state = CONNECTING;
    auto self = shared_from_this();

    sockaddr_in remote_addr;
    remote_addr.sin_family = AF_INET;

    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = m_original_dest.ip;
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);

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
    if(m_remote_socket == INVALID_SOCKET) {
        close_session();
        return;
    }
    
    int buf_size = 64 * 1024; // 64KB
    setsockopt(m_remote_socket, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
    setsockopt(m_remote_socket, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));

    BOOL nodelay = TRUE;
    setsockopt(m_remote_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

    u_long mode = 1;
    ioctlsocket(m_remote_socket, FIONBIO, &mode);
    
    if (m_is_direct) {
        WorkerPool::instance().connect_async(
            m_remote_socket, remote_addr, 
            [self]() { self->on_remote_connect(); },
            [self](char* b, int l, sockaddr_in*) { self->on_remote_read(b, l); },
            [self](int len) { self->on_write_complete(self->m_remote_socket, len); }
        );
    } else {
        WorkerPool::instance().connect_async(
            m_remote_socket, remote_addr, 
            [self]() { self->on_remote_connect(); },
            [self](char* b, int l, sockaddr_in*) { self->on_proxy_connect_response(b, l); },
            [self](int len) { self->on_write_complete(self->m_remote_socket, len); }
        );
    }
}

void ProxyTCP::on_proxy_connect_response(char* buf, int len) {
    if (len <= 0) {
        LOG_ERROR("[ProxyTCP] Proxy closed connection while awaiting CONNECT response.");
        close_session();
        return;
    }

    std::string response(buf, len);
    if (response.find(" 200 ") != std::string::npos) {
        LOG_INFO("[ProxyTCP] CONNECT tunnel established for %s", m_detected_domain.c_str());
        m_state = ESTABLISHED;

        if (!m_initial_buffer.empty()) {
            LOG_DEBUG("[ProxyTCP] Sending initial buffer (%zu bytes) to proxy tunnel", m_initial_buffer.size());
            TrafficManager::instance().report_proxy_tx((int)m_initial_buffer.size(), m_is_direct);
            WorkerPool::instance().send_async(m_remote_socket, m_initial_buffer.data(), m_initial_buffer.size());
            m_initial_buffer.clear();
        }

        auto self = shared_from_this();
        WorkerPool::instance().update_read_callback(m_remote_socket, [self](char* b, int l, sockaddr_in*) { self->on_remote_read(b, l); });

    } else {
        if (response.length() > 200) response.resize(200);
        LOG_ERROR("[ProxyTCP] Proxy CONNECT request failed. Response: %s", response.c_str());
        close_session();
    }
}

void ProxyTCP::on_remote_connect() {
    int error = 0;
    int len = sizeof(error);
    getsockopt(m_remote_socket, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
    if (error != 0) {
        LOG_ERROR("[ProxyTCP] Remote connection failed with error %d", error);
        close_session();
        return;
    }

    LOG_INFO("[ProxyTCP] Remote connection established for %s", m_detected_domain.empty() ? "(IP)" : m_detected_domain.c_str());

    auto self = shared_from_this();

    if (m_is_direct) {
        m_state = ESTABLISHED;

        if (!m_initial_buffer.empty()) {
            LOG_DEBUG("[ProxyTCP] Sending initial buffer (%zu bytes) to direct remote", m_initial_buffer.size());
            TrafficManager::instance().report_proxy_tx((int)m_initial_buffer.size(), m_is_direct);
            WorkerPool::instance().send_async(m_remote_socket, m_initial_buffer.data(), m_initial_buffer.size());
            m_initial_buffer.clear();
        }
    } else {
        m_state = AWAITING_CONNECT_RESPONSE;

        std::string target_host;
        char ip_str[INET_ADDRSTRLEN];
        if (!m_detected_domain.empty()) {
            target_host = m_detected_domain;
        } else {
            struct in_addr addr;
            addr.s_addr = m_original_dest.ip;
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            target_host = ip_str;
        }

        uint16_t target_port = ntohs(m_original_dest.port);
        std::string connect_req = "CONNECT " + target_host + ":" + std::to_string(target_port) + " HTTP/1.1\r\nHost: " + target_host + ":" + std::to_string(target_port) + "\r\n\r\n";

        LOG_DEBUG("[ProxyTCP] Sending CONNECT request to proxy for %s:%d", target_host.c_str(), target_port);
        WorkerPool::instance().send_async(m_remote_socket, (char*)connect_req.data(), (int)connect_req.length());
    }
}

void ProxyTCP::on_client_read(char* buf, int len) {
    if (len <= 0) {
        LOG_DEBUG("[ProxyTCP] Client closed connection or read error.");
        close_session();
        return;
    }

    // This read operation has completed. If not paused, post another one to keep the pipeline full.
    if (!m_client_read_paused) {
        WorkerPool::instance().read_async(m_client_socket);
    }

    TrafficManager::instance().report_proxy_tx(len, m_is_direct);
    
    if (m_state == ESTABLISHED) {
        size_t new_size;
        {
            std::lock_guard<std::mutex> lock(m_remote_queue_mutex);
            m_remote_send_queue.emplace_back(buf, buf + len);
            new_size = (m_remote_send_queue_size += len);
        }

        try_send(m_remote_socket);

        if (new_size > HIGH_WATER_MARK && !m_client_read_paused.exchange(true)) {
            LOG_DEBUG("[ProxyTCP] Backpressure applied on client read. Queue size: %zu", new_size);
        }
    } else {
        m_initial_buffer.insert(m_initial_buffer.end(), buf, buf + len);
    }
}

void ProxyTCP::on_remote_read(char* buf, int len) {
    if (len <= 0) {
        LOG_DEBUG("[ProxyTCP] Remote closed connection or read error.");
        close_session();
        return;
    }
    
    if (!m_remote_read_paused) {
        WorkerPool::instance().read_async(m_remote_socket);
    }

    TrafficManager::instance().report_proxy_rx(len, m_is_direct);

    if (m_state == ESTABLISHED) {
        size_t new_size;
        {
            std::lock_guard<std::mutex> lock(m_client_queue_mutex);
            m_client_send_queue.emplace_back(buf, buf + len);
            new_size = (m_client_send_queue_size += len);
        }
        try_send(m_client_socket);

        if (new_size > HIGH_WATER_MARK && !m_remote_read_paused.exchange(true)) {
            LOG_DEBUG("[ProxyTCP] Backpressure applied on remote read. Queue size: %zu", new_size);
        }
    }
}

void ProxyTCP::try_send(SOCKET socket) {
    if (socket == m_remote_socket) {
        std::lock_guard<std::mutex> lock(m_remote_queue_mutex);
        if (m_remote_write_in_progress || m_remote_send_queue.empty()) {
            return;
        }
        m_remote_write_in_progress = true;
        const auto& buffer_to_send = m_remote_send_queue.front();
        WorkerPool::instance().send_async(m_remote_socket, (const uint8_t*)buffer_to_send.data(), buffer_to_send.size());

    } else if (socket == m_client_socket) {
        std::lock_guard<std::mutex> lock(m_client_queue_mutex);
        if (m_client_write_in_progress || m_client_send_queue.empty()) {
            return;
        }
        m_client_write_in_progress = true;
        const auto& buffer_to_send = m_client_send_queue.front();
        WorkerPool::instance().send_async(m_client_socket, (const uint8_t*)buffer_to_send.data(), buffer_to_send.size());
    }
}

void ProxyTCP::on_write_complete(SOCKET socket, int len) {
    if (len <= 0) {
        LOG_ERROR("[ProxyTCP] Write operation failed or wrote 0 bytes, closing session. Socket: %llu", socket);
        close_session();
        return;
    }

    auto self = shared_from_this();
    if (socket == m_remote_socket) {
        size_t new_size;
        size_t sent_size = 0;
        {
            std::lock_guard<std::mutex> lock(m_remote_queue_mutex);
            if (!m_remote_send_queue.empty()) {
                sent_size = m_remote_send_queue.front().size();
                m_remote_send_queue.pop_front();
            }
            new_size = (m_remote_send_queue_size -= sent_size);
            m_remote_write_in_progress = false;
        }

        if (m_client_read_paused && new_size < LOW_WATER_MARK) {
            if (m_client_read_paused.exchange(false)) {
                 LOG_DEBUG("[ProxyTCP] Backpressure relieved on client read. Queue size: %zu", new_size);
                for (int i = 0; i < CONCURRENT_READ_COUNT; ++i) {
                    WorkerPool::instance().read_async(m_client_socket);
                }
            }
        }
        
        WorkerPool::instance().queue_task([self, socket]() {
            self->try_send(socket);
        });

    } else if (socket == m_client_socket) {
        size_t new_size;
        size_t sent_size = 0;
        {
            std::lock_guard<std::mutex> lock(m_client_queue_mutex);
            if (!m_client_send_queue.empty()) {
                sent_size = m_client_send_queue.front().size();
                m_client_send_queue.pop_front();
            }
            new_size = (m_client_send_queue_size -= sent_size);
            m_client_write_in_progress = false;
        }

        if (m_remote_read_paused && new_size < LOW_WATER_MARK) {
            if (m_remote_read_paused.exchange(false)) {
                LOG_DEBUG("[ProxyTCP] Backpressure relieved on remote read. Queue size: %zu", new_size);
                for (int i = 0; i < CONCURRENT_READ_COUNT; ++i) {
                    WorkerPool::instance().read_async(m_remote_socket);
                }
            }
        }
        
        WorkerPool::instance().queue_task([self, socket]() {
            self->try_send(socket);
        });
    }
}

void ProxyTCP::close_session() {
    if (m_state.exchange(CLOSING) == CLOSING) return;
    
    LOG_INFO("[ProxyTCP] Closing session for %s", m_detected_domain.empty() ? "(IP)" : m_detected_domain.c_str());
    if (m_client_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_client_socket);
    }
    if (m_remote_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_remote_socket);
    }
}
