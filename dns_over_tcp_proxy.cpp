#include "dns_over_tcp_proxy.h"
#include "logger.h"
#include "app_config.h"
#include "traffic_manager.h"
#include "main_dispatcher.h"

#include <ws2tcpip.h>
#include <mswsock.h>
#include <algorithm>


DnsOverTcpProxy::DnsOverTcpProxy(const std::vector<uint8_t>& query_payload, ResponseCallback callback)
    : m_state(CONNECTING),
      m_socket(INVALID_SOCKET),
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
        LOG_DEBUG("[DoT] Failed to create socket.");
        return;
    }
    
    int buf_size = 1024 * 1024; // 64KB
    setsockopt(m_socket, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
    setsockopt(m_socket, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));

    u_long mode = 1;
    ioctlsocket(m_socket, FIONBIO, &mode);
    
    sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    inet_pton(AF_INET, g_config.upstream_ip.c_str(), &proxy_addr.sin_addr);
    proxy_addr.sin_port = htons(g_config.upstream_port);

    auto self = shared_from_this();
    WorkerPool::instance().connect_async(
        m_socket, proxy_addr, 
        [self]() { self->on_connect(); },
        [self](char* buf, int len, sockaddr_in*) { self->on_read(buf, len); },
        nullptr
    );
}

void DnsOverTcpProxy::on_connect() {
    int error = 0;
    int len = sizeof(error);
    getsockopt(m_socket, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
    if (error != 0) {
        LOG_DEBUG("[DoT] Connection failed with error %d", error);
        on_close();
        return;
    }
    send_http_connect();
}

void DnsOverTcpProxy::send_http_connect() {
    m_state = HTTP_CONNECT_SENT;
    std::string target = g_config.proxy_dns_server + ":53";
    std::string req = "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n";
    WorkerPool::instance().send_async(m_socket, (char*)req.data(), (int)req.length());
}

void DnsOverTcpProxy::send_dns_query() {
    m_state = DNS_QUERY;
    uint16_t len = htons((uint16_t)m_query_payload.size());
    std::vector<uint8_t> tcp_pkt;
    tcp_pkt.reserve(2 + m_query_payload.size());
    tcp_pkt.push_back(((uint8_t*)&len)[0]);
    tcp_pkt.push_back(((uint8_t*)&len)[1]);
    tcp_pkt.insert(tcp_pkt.end(), m_query_payload.begin(), m_query_payload.end());

    TrafficManager::instance().report_proxy_tx((int)tcp_pkt.size(), false);
    WorkerPool::instance().send_async(m_socket, tcp_pkt.data(), tcp_pkt.size());
}

void DnsOverTcpProxy::on_read(char* buf, int len) {
    if (len <= 0) {
        on_close();
        return;
    }

    m_read_buffer.insert(m_read_buffer.end(), buf, buf + len);
    TrafficManager::instance().report_proxy_rx(len, false);

    if (m_state == HTTP_CONNECT_SENT) {
        const char* crlf2 = "\r\n\r\n";
        auto it = std::search(m_read_buffer.begin(), m_read_buffer.end(), crlf2, crlf2 + 4);

        if (it != m_read_buffer.end()) {
            std::string header(m_read_buffer.begin(), it);
            if (header.find(" 200 ") != std::string::npos) {
                m_read_buffer.erase(m_read_buffer.begin(), it + 4);
                send_dns_query();
            } else {
                LOG_DEBUG("[DoT] Proxy CONNECT failed: %s", header.c_str());
                on_close();
                return;
            }
        }
    }
    
    else if (m_state == DNS_QUERY) {
        handle_dns_response();
    }

    if (m_state != CLOSED) {
        WorkerPool::instance().read_async(m_socket);
    }
}

void DnsOverTcpProxy::handle_dns_response() {
    while (m_state == DNS_QUERY && !m_read_buffer.empty()) {
        if (!m_len_received) {
            if (m_read_buffer.size() >= 2) {
                m_expected_len = (uint16_t)(((uint16_t)m_read_buffer[0] << 8) | m_read_buffer[1]);
                m_len_received = true;
                m_read_buffer.erase(m_read_buffer.begin(), m_read_buffer.begin() + 2);
            } else {
                break;
            }
        }

        if (m_len_received) {
            if (m_read_buffer.size() >= m_expected_len) {
                m_callback((const char*)m_read_buffer.data(), m_expected_len);

                m_read_buffer.erase(m_read_buffer.begin(), m_read_buffer.begin() + m_expected_len);
                m_len_received = false;
                m_expected_len = 0;

                on_close();
                break;
            } else {
                break;
            }
        }
    }
}

void DnsOverTcpProxy::on_write(int len) {
}

void DnsOverTcpProxy::on_close() {
    if (m_state == CLOSED) return;
    m_state = CLOSED;
    if (m_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_socket);
        m_socket = INVALID_SOCKET;
    }
}
