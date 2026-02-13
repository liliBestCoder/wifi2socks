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
    m_worker = WorkerPool::instance().get_next_worker();
    if (!m_worker) {
        LOG_ERROR("[DoT] No available workers.");
        return;
    }

    m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_socket == INVALID_SOCKET) {
        LOG_ERROR("[DoT] Failed to create socket.");
        return;
    }
    
    u_long mode = 1;
    ioctlsocket(m_socket, FIONBIO, &mode);
    
    sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    inet_pton(AF_INET, g_config.proxy_ip.c_str(), &proxy_addr.sin_addr);
    proxy_addr.sin_port = htons(g_config.proxy_port);

    auto self = shared_from_this();
    m_worker->connect_async(m_socket, proxy_addr, [self]() {
        self->on_connect();
    });
}

void DnsOverTcpProxy::on_connect() {
    auto self = shared_from_this();
    m_worker->add_socket(
        m_socket,
        [self](char* buf, int len, sockaddr_in*) { self->on_read(buf, len); },
        [self](int len) { self->on_write(len); },
        [self]() { self->on_close(); }
    );
    send_socks5_auth();
}

void DnsOverTcpProxy::send_socks5_auth() {
    m_state = SOCKS5_AUTH;
    unsigned char req[] = { 0x05, 0x01, 0x00 };
    m_worker->send_async(m_socket, (char*)req, sizeof(req));
}

void DnsOverTcpProxy::send_socks5_connect() {
    m_state = SOCKS5_CONNECT;
    std::vector<unsigned char> req = { 0x05, 0x01, 0x00, 0x01 }; // SOCKS5, CONNECT, RSV, IPv4
    
    uint32_t dns_ip;
    inet_pton(AF_INET, g_config.proxy_dns_server.c_str(), &dns_ip);
    req.push_back(dns_ip & 0xFF);
    req.push_back((dns_ip >> 8) & 0xFF);
    req.push_back((dns_ip >> 16) & 0xFF);
    req.push_back((dns_ip >> 24) & 0xFF);
    
    uint16_t dns_port = htons(53); 
    req.push_back(dns_port & 0xFF);
    req.push_back((dns_port >> 8) & 0xFF);

    m_worker->send_async(m_socket, (char*)req.data(), (int)req.size());
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
    m_worker->send_async(m_socket, (char*)tcp_pkt.data(), (int)tcp_pkt.size());
}

void DnsOverTcpProxy::on_read(char* buf, int len) {
    if (len <= 0) {
        on_close();
        return;
    }

    if (m_state == SOCKS5_AUTH) {
        handle_socks5_auth_response(buf, len);
    } else if (m_state == SOCKS5_CONNECT) {
        handle_socks5_connect_response(buf, len);
    } else if (m_state == DNS_QUERY) {
        handle_dns_response(buf, len);
    }
}

void DnsOverTcpProxy::handle_socks5_auth_response(const char* buf, int len) {
    if (len >= 2 && (unsigned char)buf[0] == 0x05 && (unsigned char)buf[1] == 0x00) {
        send_socks5_connect();
    } else {
        on_close();
    }
}

void DnsOverTcpProxy::handle_socks5_connect_response(const char* buf, int len) {
    if (len >= 4 && (unsigned char)buf[0] == 0x05 && (unsigned char)buf[1] == 0x00) {
        send_dns_query();
    } else {
        on_close();
    }
}

void DnsOverTcpProxy::handle_dns_response(const char* buf, int len) {
    TrafficManager::instance().report_proxy_rx(len, false);
    m_read_buffer.insert(m_read_buffer.end(), buf, buf + len);

    while (true) {
        if (!m_len_received) {
            if (m_read_buffer.size() >= 2) {
                m_expected_len = ntohs(*(uint16_t*)m_read_buffer.data());
                m_len_received = true;
                m_read_buffer.erase(m_read_buffer.begin(), m_read_buffer.begin() + 2);
            } else break;
        }

        if (m_len_received) {
            if (m_read_buffer.size() >= m_expected_len) {
                m_callback((const char*)m_read_buffer.data(), m_expected_len);
                on_close();
                break;
            } else {
                break;
            }
        }
    }
}

void DnsOverTcpProxy::on_write(int len) {
    // This is called after a send operation completes. We can post another read.
    // The worker loop already does this, so this can be a no-op for now.
}

void DnsOverTcpProxy::on_close() {
    if (m_state == CLOSED) return;
    m_state = CLOSED;
    if (m_socket != INVALID_SOCKET) {
        m_worker->remove_socket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    // The object will be destroyed when the last shared_ptr goes out of scope.
}
