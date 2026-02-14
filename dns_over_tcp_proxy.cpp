#include "dns_over_tcp_proxy.h"
#include "logger.h"
#include "app_config.h"
#include "traffic_manager.h"
#include "main_dispatcher.h"

#include <ws2tcpip.h>
#include <mswsock.h>


DnsOverTcpProxy::DnsOverTcpProxy(const std::vector<uint8_t>& query_payload, ResponseCallback callback)
    : m_state(CONNECTING),
      m_socket(INVALID_SOCKET),
      m_worker(nullptr),
      m_query_payload(query_payload),
      m_callback(callback),
      m_expected_len(0),
      m_len_received(false)
{
}

DnsOverTcpProxy::~DnsOverTcpProxy() {
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
    }
}

void DnsOverTcpProxy::start() {
    m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_socket == INVALID_SOCKET) {
        LOG_ERROR("[DoT] Failed to create socket.");
        return;
    }
    
    int buf_size = 1024 * 1024; // 1MB
    setsockopt(m_socket, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
    setsockopt(m_socket, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));

    u_long mode = 1;\n    ioctlsocket(m_socket, FIONBIO, &mode);
    
    sockaddr_in proxy_addr;\n    proxy_addr.sin_family = AF_INET;\n    inet_pton(AF_INET, g_config.proxy_ip.c_str(), &proxy_addr.sin_addr);\n    proxy_addr.sin_port = htons(g_config.proxy_port);

    auto self = shared_from_this();
    WorkerPool::instance().connect_async(m_socket, proxy_addr, [self]() {
        self->on_connect();
    });
}

void DnsOverTcpProxy::on_connect() {
    auto self = shared_from_this();\n    WorkerPool::instance().add_socket(
        m_socket,
        [self](char* buf, int len, sockaddr_in*) { self->on_read(buf, len); },
        nullptr, // on_write no longer needed
        [self]() { self->on_close(); }
    );
    send_http_connect();
}

void DnsOverTcpProxy::send_http_connect() {
    m_state = HTTP_CONNECT_SENT;\n    std::string target = g_config.proxy_dns_server + ":53";\n    std::string req = "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n";
    WorkerPool::instance().send_async(m_socket, (char*)req.data(), (int)req.length());
}

void DnsOverTcpProxy::send_dns_query() {
    m_state = DNS_QUERY;\n    uint16_t len = htons((uint16_t)m_query_payload.size());\n    std::vector<uint8_t> tcp_pkt;\n    tcp_pkt.reserve(2 + m_query_payload.size());\n    tcp_pkt.push_back(((uint8_t*)&len)[0]);\n    tcp_pkt.push_back(((uint8_t*)&len)[1]);\n    tcp_pkt.insert(tcp_pkt.end(), m_query_payload.begin(), m_query_payload.end());

    TrafficManager::instance().report_proxy_tx((int)tcp_pkt.size(), false);
    WorkerPool::instance().send_async(m_socket, std::move(tcp_pkt));
}

void DnsOverTcpProxy::on_read(char* buf, int len) {
    if (len <= 0) {
        on_close();\n        return;
    }\n\n    if (m_state == HTTP_CONNECT_SENT) {
        std::string resp(buf, len);\n        if (resp.find(" 200 ") != std::string::npos) {
            send_dns_query();\n        } else {
            LOG_ERROR("[DoT] Proxy CONNECT failed: %s", resp.c_str());\n            on_close();\n        }\n    } else if (m_state == DNS_QUERY) {
        handle_dns_response(buf, len);\n    }
}

void DnsOverTcpProxy::handle_dns_response(const char* buf, int len) {
    TrafficManager::instance().report_proxy_rx(len, false);\n    m_read_buffer.insert(m_read_buffer.end(), buf, buf + len);

    while (true) {
        if (!m_len_received) {
            if (m_read_buffer.size() >= 2) {
                m_expected_len = ntohs(*(uint16_t*)m_read_buffer.data());\n                m_len_received = true;\n                m_read_buffer.erase(m_read_buffer.begin(), m_read_buffer.begin() + 2);\n            } else break;\n        }

        if (m_len_received) {
            if (m_read_buffer.size() >= m_expected_len) {
                m_callback((const char*)m_read_buffer.data(), m_expected_len);\n                on_close();\n                break;\n            } else {\n                break;\n            }\n        }\n    }
}

void DnsOverTcpProxy::on_write(int len) {
}

void DnsOverTcpProxy::on_close() {
    if (m_state == CLOSED) return;\n    m_state = CLOSED;\n    if (m_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_socket);\n        m_socket = INVALID_SOCKET;\n    }
}