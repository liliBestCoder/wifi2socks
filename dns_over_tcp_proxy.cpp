#include "dns_over_tcp_proxy.h"
#include "logger.h"
#include "app_config.h"
#include "traffic_manager.h"
#include "main_dispatcher.h"

#include <ws2tcpip.h>
#include <mswsock.h>

extern LPFN_CONNECTEX get_connect_ex(); // Reuse the helper from proxy_tcp.cpp

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
    m_worker = WorkerPool::instance().get_worker();
    if (!m_worker) {
        LOG_ERROR("[DoT] No available workers.");
        return;
    }

    m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    u_long mode = 1;
    ioctlsocket(m_socket, FIONBIO, &mode);

    sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;
    bind(m_socket, (SOCKADDR*)&bind_addr, sizeof(bind_addr));

    auto self = shared_from_this();
    m_worker->add_socket(
        m_socket,
        this,
        [self](char* buf, int len) { self->on_read(buf, len); },
        [self](int len) { self->on_write(len); },
        [self]() { self->on_close(); }
    );

    sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    inet_pton(AF_INET, g_config.proxy_ip.c_str(), &proxy_addr.sin_addr);
    proxy_addr.sin_port = htons(g_config.proxy_port);

    auto connect_ex = get_connect_ex();
    if (!connect_ex || !connect_ex(m_socket, (SOCKADDR*)&proxy_addr, sizeof(proxy_addr), NULL, 0, NULL, m_worker->get_overlapped_for_connect(m_socket))) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            LOG_ERROR("[DoT] ConnectEx failed: %d", WSAGetLastError());
            on_close();
        }
    }
}

void DnsOverTcpProxy::on_connect() {
    setsockopt(m_socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
    send_socks5_auth();
}

void DnsOverTcpProxy::send_socks5_auth() {
    m_state = SOCKS5_AUTH;
    unsigned char req[] = { 0x05, 0x01, 0x00 };
    m_worker->write_async(m_socket, (char*)req, sizeof(req));
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
    
    uint16_t dns_port = htons(53); // Or 853 for DoT, but standard DNS over TCP uses 53
    req.push_back(dns_port & 0xFF);
    req.push_back((dns_port >> 8) & 0xFF);

    m_worker->write_async(m_socket, (char*)req.data(), (int)req.size());
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
    m_worker->write_async(m_socket, (char*)tcp_pkt.data(), (int)tcp_pkt.size());
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
            } else break;
        }

        if (m_len_received) {
            if (m_read_buffer.size() >= (size_t)2 + m_expected_len) {
                // We have a full DNS response
                m_callback((const char*)m_read_buffer.data() + 2, m_expected_len);
                
                // For a simple DNS proxy, we close after one response
                on_close();
                break;
            } else {
                // Need more data
                m_worker->read_async(m_socket);
                break;
            }
        }
    }
}

void DnsOverTcpProxy::on_write(int len) {
    if (len > 0) {
        m_worker->read_async(m_socket);
    }
}

void DnsOverTcpProxy::on_close() {
    m_state = CLOSED;
    if (m_socket != INVALID_SOCKET) {
        m_worker->remove_socket(m_socket);
        m_socket = INVALID_SOCKET;
    }
}
