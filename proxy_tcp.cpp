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

    int buf_size = 1024 * 1024; // 1MB
    setsockopt(m_client_socket, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
    setsockopt(m_client_socket, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));
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
        nullptr, 
        nullptr
    );
}

void ProxyTCP::on_client_initial_read(char* buf, int len) {
    if (len <= 0) {
        close_session();
        return;
    }

    size_t max_len = (g_config.max_sni_len > 0) ? g_config.max_sni_len : 16384;
    if (m_initial_buffer.size() + len > max_len) {
        LOG_INFO("[ProxyTCP] Initial buffer exceeded limit. Deciding with current data.");
        len = (int)(max_len - m_initial_buffer.size());
    }

    if (len > 0) {
        m_initial_buffer.insert(m_initial_buffer.end(), (const uint8_t*)buf, (const uint8_t*)buf + len);
    }

    if (ntohs(m_original_dest.port) == 80 && is_generate_204_request(m_initial_buffer.data(), m_initial_buffer.size())) {
        LOG_INFO("[ProxyTCP] Intercepted /generate_204. Sending mock response.");
        const char* resp204 = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
        send(m_client_socket, resp204, (int)strlen(resp204), 0);
        close_session();
        return;
    }

    bool ready_to_decide = false;
    std::string domain = parse_tls_sni(m_initial_buffer.data(), m_initial_buffer.size());
    if (!domain.empty()) {
        m_detected_domain = domain;
        ready_to_decide = true;
    } else if (is_http_start(m_initial_buffer.data(), m_initial_buffer.size())) {
        domain = parse_http_host(m_initial_buffer.data(), m_initial_buffer.size());
        if (!domain.empty()) {
            m_detected_domain = domain;
            ready_to_decide = true;
        }
    }

    if (!ready_to_decide && m_initial_buffer.size() < max_len) {
        return;
    }

    if (!m_detected_domain.empty()) {
        RouteAction rule = RuleManager::instance().match_domain(m_detected_domain);
        if (rule == RouteAction::DIRECT) m_is_direct = true;
        else if (rule == RouteAction::PROXY) m_is_direct = false;
        else m_is_direct = GeoChecker::instance().is_cn_domain(m_detected_domain);
    } else {
        uint32_t ip_h = ntohl(m_original_dest.ip);
        RouteAction rule = RuleManager::instance().match_ip(ip_h);
        
        if (GeoChecker::is_private_ip(ip_h)) {
            m_is_direct = true;
        } else if (rule == RouteAction::DIRECT) {
            m_is_direct = true;
        } else if (rule == RouteAction::PROXY) {
            m_is_direct = false;
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
    
    int buf_size = 1024 * 1024; // 1MB
    setsockopt(m_remote_socket, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
    setsockopt(m_remote_socket, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));

    u_long mode = 1;
    ioctlsocket(m_remote_socket, FIONBIO, &mode);
    
    if (m_is_direct) {
        WorkerPool::instance().connect_async(
            m_remote_socket, remote_addr, 
            [self]() { self->on_remote_connect(); },
            [self](char* b, int l, sockaddr_in*) { self->on_remote_read(b, l); },
            nullptr,
            nullptr
        );
    } else {
        WorkerPool::instance().connect_async(
            m_remote_socket, remote_addr, 
            [self]() { self->on_remote_connect(); },
            [self](char* b, int l, sockaddr_in*) { self->on_proxy_connect_response(b, l); },
            nullptr,
            nullptr
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
            WorkerPool::instance().send_async(m_remote_socket, std::move(m_initial_buffer));
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
            WorkerPool::instance().send_async(m_remote_socket, std::move(m_initial_buffer));
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
        LOG_DEBUG("[ProxyTCP] Client closed connection.");
        close_session();
        return;
    }
    TrafficManager::instance().report_proxy_tx(len, m_is_direct);
    
    if (m_state == ESTABLISHED) {
        WorkerPool::instance().send_async(m_remote_socket, buf, len);
    } else {
        m_initial_buffer.insert(m_initial_buffer.end(), buf, buf + len);
    }
}

void ProxyTCP::on_remote_read(char* buf, int len) {
    if (len <= 0) {
        LOG_DEBUG("[ProxyTCP] Remote closed connection.");
        close_session();
        return;
    }
    TrafficManager::instance().report_proxy_rx(len, m_is_direct);
    
    if (m_state == ESTABLISHED) {
        WorkerPool::instance().send_async(m_client_socket, buf, len);
    }
}

void ProxyTCP::close_session() {
    if (m_state == CLOSING) return;
    m_state = CLOSING;
    LOG_INFO("[ProxyTCP] Closing session for %s", m_detected_domain.empty() ? "(IP)" : m_detected_domain.c_str());
    if (m_client_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_client_socket);
        m_client_socket = INVALID_SOCKET;
    }
    if (m_remote_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_remote_socket);
        m_remote_socket = INVALID_SOCKET;
    }
}