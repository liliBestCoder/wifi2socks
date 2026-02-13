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

// --- HTTP Parsing Helpers ---
bool is_http_start(const uint8_t* data, size_t len) {
    if (len < 4) return false;
    return (memcmp(data, "GET ", 4) == 0 || memcmp(data, "POST", 4) == 0 || 
            memcmp(data, "HEAD", 4) == 0 || memcmp(data, "PUT ", 4) == 0 ||
            memcmp(data, "CONN", 4) == 0); // CONNECT
}

std::string parse_http_host(const uint8_t* data, size_t len) {
    std::string s((const char*)data, len);
    size_t pos = s.find("Host: ");
    if (pos == std::string::npos) return "";
    pos += 6;
    size_t end = s.find("\r\n", pos);
    if (end == std::string::npos) return "";
    std::string host = s.substr(pos, end - pos);
    size_t port_pos = host.find(':');
    if (port_pos != std::string::npos) host = host.substr(0, port_pos);
    return host;
}

bool is_generate_204_request(const uint8_t* data, size_t len) {
    if (len < 20) return false;
    // Check for "GET /generate_204"
    return (memcmp(data, "GET /generate_204", 17) == 0);
}

// Helper to get ConnectEx function pointer
LPFN_CONNECTEX get_connect_ex() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return nullptr;
    GUID guid = WSAID_CONNECTEX;
    LPFN_CONNECTEX connect_ex = nullptr;
    DWORD bytes = 0;
    WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &connect_ex, sizeof(connect_ex), &bytes, NULL, NULL);
    closesocket(s);
    return connect_ex;
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
    // Set sockets to non-blocking
    u_long mode = 1;
    ioctlsocket(m_client_socket, FIONBIO, &mode);
}

ProxyTCP::~ProxyTCP() {
    if (m_client_socket != INVALID_SOCKET) {
        closesocket(m_client_socket);
    }
    if (m_remote_socket != INVALID_SOCKET) {
        closesocket(m_remote_socket);
    }
    LOG_DEBUG("[ProxyTCP] Session destroyed.");
}

void ProxyTCP::start() {
    m_worker = WorkerPool::instance().get_worker(m_original_dest.port);
    if (!m_worker) {
        LOG_ERROR("[ProxyTCP] No available workers. Closing session.");
        close_session();
        return;
    }

    // Add client socket to IOCP for initial read
    auto self = shared_from_this();
    retain(); // Increment ref count for the client socket
    m_worker->add_socket(
        m_client_socket,
        [self](char* buf, int len, sockaddr_in*) { self->on_client_initial_read(buf, len); },
        nullptr, // No write callback initially
        [self]() { self->on_close(); }
    );
    // The worker's loop will automatically post the first read.
}

void ProxyTCP::on_client_initial_read(char* buf, int len) {
    if (len <= 0) {
        close_session();
        return;
    }

    // Limit buffer size to prevent memory abuse
    size_t max_len = (g_config.max_sni_len > 0) ? g_config.max_sni_len : 16384;
    if (m_initial_buffer.size() + len > max_len) {
        LOG_INFO("[ProxyTCP] Initial buffer exceeded limit. Deciding with current data.");
        len = (int)(max_len - m_initial_buffer.size());
    }

    if (len > 0) {
        m_initial_buffer.insert(m_initial_buffer.end(), (const uint8_t*)buf, (const uint8_t*)buf + len);
    }

    // 1. Check for /generate_204 Mock (Port 80)
    if (ntohs(m_original_dest.port) == 80 && is_generate_204_request(m_initial_buffer.data(), m_initial_buffer.size())) {
        LOG_INFO("[ProxyTCP] Intercepted /generate_204. Sending mock response.");
        const char* resp204 = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
        send(m_client_socket, resp204, (int)strlen(resp204), 0);
        close_session();
        return;
    }

    // 2. Try to parse Domain (SNI or Host)
    bool ready_to_decide = false;
    std::string domain = TlsParser::parse_client_hello((const char*)m_initial_buffer.data(), m_initial_buffer.size());
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

    // If still not ready, and we haven't hit the buffer limit, wait for more data.
    // The worker loop will automatically post another read.
    if (!ready_to_decide && m_initial_buffer.size() < max_len) {
        return;
    }

    // 3. Routing Decision (Priority: RuleManager > GeoChecker > IP)
    if (!m_detected_domain.empty()) {
        RuleAction rule = RuleManager::instance().match_domain(m_detected_domain);
        if (rule == RULE_DIRECT) {
            m_is_direct = true;
        } else if (rule == RULE_PROXY) {
            m_is_direct = false;
        } else { // RULE_PASS
            m_is_direct = GeoChecker::instance().is_cn_domain(m_detected_domain);
        }
    } else {
        // No domain detected, fallback to IP-based routing
        uint32_t ip_h = ntohl(m_original_dest.ip);
        RuleAction rule = RuleManager::instance().match_ip(ip_h);
        if (rule == RULE_DIRECT) {
            m_is_direct = true;
        } else if (rule == RULE_PROXY) {
            m_is_direct = false;
        } else { // RULE_PASS
            m_is_direct = GeoChecker::instance().is_cn_ip(ip_h);
        }
    }
    
    auto self = shared_from_this();
    m_worker->update_read_callback(m_client_socket, [self](char* b, int l, sockaddr_in*) { self->on_client_read(b, l); });
    
    // 4. Connect to remote
    connect_remote();
}

void ProxyTCP::connect_remote() {
    m_state = CONNECTING;

    sockaddr_in remote_addr;\n    remote_addr.sin_family = AF_INET;

    if (m_is_direct) {
        LOG_INFO("[ProxyTCP] Routing DIRECT for %s (IP: %s)", 
            m_detected_domain.empty() ? "(IP)" : m_detected_domain.c_str(),
            inet_ntoa({.s_addr = m_original_dest.ip}));
        remote_addr.sin_addr.s_addr = m_original_dest.ip;\n        remote_addr.sin_port = m_original_dest.port;
    } else {
        LOG_INFO("[ProxyTCP] Routing PROXY for %s", m_detected_domain.empty() ? inet_ntoa({.s_addr = m_original_dest.ip}) : m_detected_domain.c_str());
        inet_pton(AF_INET, g_config.proxy_ip.c_str(), &remote_addr.sin_addr);
        remote_addr.sin_port = htons(g_config.proxy_port);
    }
    
    m_remote_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    u_long mode = 1;
    ioctlsocket(m_remote_socket, FIONBIO, &mode);
    
    sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;
    bind(m_remote_socket, (SOCKADDR*)&bind_addr, sizeof(bind_addr));

    retain();
    m_worker->add_socket(
        m_remote_socket,
        this,
        [this](char* buf, int len) { on_remote_read(buf, len); },
        [this](int len) { on_remote_write(len); },
        [this]() { on_close(); }
    );

    auto connect_ex = get_connect_ex();
    if (!connect_ex || !connect_ex(m_remote_socket, (SOCKADDR*)&remote_addr, sizeof(remote_addr), NULL, 0, NULL, m_worker->get_overlapped_for_connect(m_remote_socket))) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            LOG_ERROR("[ProxyTCP] ConnectEx failed: %d", WSAGetLastError());
            on_close();
        }
    }
}

void ProxyTCP::on_remote_connect() {
    LOG_DEBUG("[ProxyTCP] Remote connection established.");
    m_state = ESTABLISHED;
    setsockopt(m_remote_socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
    m_worker->read_async(m_remote_socket);

    if (!m_initial_buffer.empty()) {
        TrafficManager::instance().report_proxy_tx((int)m_initial_buffer.size(), m_is_direct);
        m_remote_write_busy = true;
        m_worker->write_async(m_remote_socket, (char*)m_initial_buffer.data(), (int)m_initial_buffer.size());
        m_initial_buffer.clear();
    }
}

void ProxyTCP::on_client_read(char* buf, int len) {
    if (len <= 0) {
        close_session();
        return;
    }
    TrafficManager::instance().report_proxy_tx(len, m_is_direct);
    if (m_state == ESTABLISHED && !m_remote_write_busy) {
        m_remote_write_busy = true;
        m_worker->write_async(m_remote_socket, buf, len);
    }
}

void ProxyTCP::on_remote_read(char* buf, int len) {
    if (len <= 0) {
        close_session();
        return;
    }
    TrafficManager::instance().report_proxy_rx(len, m_is_direct);
    if (m_state == ESTABLISHED && !m_client_write_busy) {
        m_client_write_busy = true;
        m_worker->write_async(m_client_socket, buf, len);
    }
}

void ProxyTCP::on_client_write(int len) {
    m_client_write_busy = false;
}

void ProxyTCP::on_remote_write(int len) {
    m_remote_write_busy = false;
    if (m_state == ESTABLISHED) {
        m_worker->read_async(m_client_socket);
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