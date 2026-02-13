#pragma once

#include <winsock2.h>
#include <vector>
#include <memory>
#include <functional>
#include <string>
#include "worker.h"

class DnsOverTcpProxy : public std::enable_shared_from_this<DnsOverTcpProxy> {
public:
    using ResponseCallback = std::function<void(const char* data, int len)>;

    DnsOverTcpProxy(const std::vector<uint8_t>& query_payload, ResponseCallback callback);
    ~DnsOverTcpProxy();

    void start();

private:
    void on_connect();
    void on_read(char* buf, int len);
    void on_write(int len);
    void on_close();

    void send_socks5_auth();
    void send_socks5_connect();
    void send_dns_query();
    void handle_socks5_auth_response(const char* buf, int len);
    void handle_socks5_connect_response(const char* buf, int len);
    void handle_dns_response(const char* buf, int len);

    enum State {
        CONNECTING,
        SOCKS5_AUTH,
        SOCKS5_CONNECT,
        DNS_QUERY,
        CLOSED
    };

    State m_state;
    SOCKET m_socket;
    Worker* m_worker;
    std::vector<uint8_t> m_query_payload;
    ResponseCallback m_callback;
    std::vector<uint8_t> m_read_buffer;
    
    // For DNS-over-TCP, we expect exactly one response
    uint16_t m_expected_len;
    bool m_len_received;
};
