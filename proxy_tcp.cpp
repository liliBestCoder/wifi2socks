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
      m_worker(nullptr),
      m_is_direct(false),
      m_client_write_busy(false),
      m_remote_write_busy(false),
      m_ref_count(0)
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
    m_worker = WorkerPool::instance().get_worker(m_original_dest.port);
    if (!m_worker) {
        LOG_ERROR("[ProxyTCP] No available workers. Closing session.");
        close_session();
        return;
    }

    auto self = shared_from_this();
    retain(); 
    m_worker->add_socket(
        m_client_socket,
        [self](char* buf, int len, sockaddr_in*) { self->on_client_initial_read(buf, len); },
        [self](int len) { self->on_client_write(len); }, 
        [self]() { self->on_close(); }
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
        if (rule == RouteAction::DIRECT) m_is_direct = true;
        else if (rule == RouteAction::PROXY) m_is_direct = false;
        else m_is_direct = GeoChecker::instance().is_cn_ip(ip_h);
    }
    
    auto self = shared_from_this();
    m_worker->update_read_callback(m_client_socket, [self](char* b, int l, sockaddr_in*) { self->on_client_read(b, l); });
    
    connect_remote();
}

void ProxyTCP::connect_remote() {
    m_state = CONNECTING;
    auto self = shared_from_this();

    sockaddr_in remote_addr;
    remote_addr.sin_family = AF_INET;

    if (m_is_direct) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &m_original_dest.ip, ip_str, INET_ADDRSTRLEN);
        LOG_INFO("[ProxyTCP] Routing DIRECT for %s (IP: %s)", m_detected_domain.empty() ? "(IP)" : m_detected_domain.c_str(), ip_str);
        remote_addr.sin_addr.s_addr = m_original_dest.ip;
        remote_addr.sin_port = m_original_dest.port;
    } else {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &m_original_dest.ip, ip_str, INET_ADDRSTRLEN);
        LOG_INFO("[ProxyTCP] Routing PROXY for %s", m_detected_domain.empty() ? ip_str : m_detected_domain.c_str());
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
    
    m_worker->connect_async(m_remote_socket, remote_addr, [self]() {
        self->on_remote_connect();
    });
}

void ProxyTCP::on_proxy_connect_response(char* buf, int len) {
    if (len <= 0) {
        LOG_ERROR("[ProxyTCP] Proxy closed connection while awaiting CONNECT response.");
        close_session();
        return;
    }

    std::string response(buf, len);
    // Be lenient with the response check, just look for 200
    if (response.find(" 200 ") != std::string::npos) {
        LOG_INFO("[ProxyTCP] CONNECT tunnel established for %s", m_detected_domain.c_str());
        m_state = ESTABLISHED;

        // The tunnel is ready, now we can send the initial data that we buffered
        if (!m_initial_buffer.empty()) {
            TrafficManager::instance().report_proxy_tx((int)m_initial_buffer.size(), m_is_direct);
            m_remote_write_busy = true;
            m_worker->send_async(m_remote_socket, (char*)m_initial_buffer.data(), (int)m_initial_buffer.size());
            m_initial_buffer.clear();
        }

        // Now that the tunnel is established, switch to normal data forwarding
        auto self = shared_from_this();
        m_worker->update_read_callback(m_remote_socket, [self](char* b, int l, sockaddr_in*) { self->on_remote_read(b, l); });

    } else {
        // Truncate for logging
        if (response.length() > 200) {
            response.resize(200);
        }
        LOG_ERROR("[ProxyTCP] Proxy CONNECT request failed. Response: %s", response.c_str());
        close_session();
    }
}

void ProxyTCP::on_remote_connect() {
    LOG_DEBUG("[ProxyTCP] Physical connection to remote established.");

    auto self = shared_from_this();
    retain();

    if (m_is_direct) {
        m_state = ESTABLISHED;
        m_worker->add_socket(
            m_remote_socket,
            [self](char* buf, int len, sockaddr_in*) { self->on_remote_read(buf, len); },
            [self](int len) { self->on_remote_write(len); },
            [self]() { self->on_close(); }
        );

        if (!m_initial_buffer.empty()) {
            TrafficManager::instance().report_proxy_tx((int)m_initial_buffer.size(), m_is_direct);
            m_remote_write_busy = true;
            m_worker->send_async(m_remote_socket, (char*)m_initial_buffer.data(), (int)m_initial_buffer.size());
            m_initial_buffer.clear();
        }
    } else {
        // We are connected to the proxy, now send the HTTP CONNECT request
        m_state = AWAITING_CONNECT_RESPONSE;

        m_worker->add_socket(
            m_remote_socket,
            [self](char* buf, int len, sockaddr_in*) { self->on_proxy_connect_response(buf, len); },
            [self](int len) { self->on_remote_write(len); },
            [self]() { self->on_close(); }
        );

        std::string target_host;
        char ip_str[INET_ADDRSTRLEN];
        if (!m_detected_domain.empty()) {
            target_host = m_detected_domain;
        } else {
            inet_ntop(AF_INET, &m_original_dest.ip, ip_str, INET_ADDRSTRLEN);
            target_host = ip_str;
        }

        uint16_t target_port = ntohs(m_original_dest.port);

        std::string connect_req = "CONNECT " + target_host + ":" + std::to_string(target_port) + " HTTP/1.1\r\nHost: " + target_host + ":" + std::to_string(target_port) + "\r\n\r\n";

        LOG_DEBUG("[ProxyTCP] Sending CONNECT request to proxy for %s:%d", target_host.c_str(), target_port);

        m_remote_write_busy = true;
        m_worker->send_async(m_remote_socket, (char*)connect_req.data(), (int)connect_req.length());
    }
}

void ProxyTCP::on_client_read(char* buf, int len) {
    if (len <= 0) {
        close_session();
        return;
    }
    TrafficManager::instance().report_proxy_tx(len, m_is_direct);
    
    if (m_state == ESTABLISHED) {
        if (!m_remote_write_busy) {
            m_remote_write_busy = true;
            m_worker->send_async(m_remote_socket, buf, len);
        } else {
            m_remote_outbox.insert(m_remote_outbox.end(), buf, buf + len);
        }
    } else {
        // Still connecting, buffer the data to be sent once established
        m_initial_buffer.insert(m_initial_buffer.end(), buf, buf + len);
    }
}

void ProxyTCP::on_remote_read(char* buf, int len) {
    if (len <= 0) {
        close_session();
        return;
    }
    TrafficManager::instance().report_proxy_rx(len, m_is_direct);
    
    if (m_state == ESTABLISHED) {
        if (!m_client_write_busy) {
            m_client_write_busy = true;
            m_worker->send_async(m_client_socket, buf, len);
        } else {
            m_client_outbox.insert(m_client_outbox.end(), buf, buf + len);
        }
    }
    // If not established, we shouldn't really be receiving data from remote yet
}

void ProxyTCP::on_client_write(int len) {
    if (!m_client_outbox.empty()) {
        m_worker->send_async(m_client_socket, std::move(m_client_outbox));
        m_client_outbox.clear();
        // m_client_write_busy remains true
    } else {
        m_client_write_busy = false;
    }
}

void ProxyTCP::on_remote_write(int len) {
    if (!m_remote_outbox.empty()) {
        m_worker->send_async(m_remote_socket, std::move(m_remote_outbox));
        m_remote_outbox.clear();
        // m_remote_write_busy remains true
    } else {
        m_remote_write_busy = false;
    }
}

void ProxyTCP::on_close() {
    release();
}

void ProxyTCP::close_session() {
    if (m_state == CLOSING) return;
    m_state = CLOSING;
    LOG_DEBUG("[ProxyTCP] Closing session.");
    if (m_client_socket != INVALID_SOCKET) {
        m_worker->remove_socket(m_client_socket);
        m_client_socket = INVALID_SOCKET;
    }
    if (m_remote_socket != INVALID_SOCKET) {
        m_worker->remove_socket(m_remote_socket);
        m_remote_socket = INVALID_SOCKET;
    }
}

void ProxyTCP::retain() {
    ++m_ref_count;
}

void ProxyTCP::release() {
    if (--m_ref_count == 0) {
        MainDispatcher::instance().queue_task([self = shared_from_this()]() {});
    }
}
