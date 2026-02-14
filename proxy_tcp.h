#pragma once

#include <winsock2.h>
#include <memory>
#include <vector>
#include <string>
#include <atomic>

#include "worker.h"
#include "nat_manager.h"

class ProxyTCP : public std::enable_shared_from_this<ProxyTCP> {
public:
    // Constructor takes the already-accepted client socket and its original destination.
    ProxyTCP(SOCKET client_socket, OriginalDestination dest);
    ~ProxyTCP();

    // Starts the proxy session.
    void start();

private:
    void on_client_initial_read(char* buf, int len);
    void connect_remote();
    void on_remote_connect();
    void on_proxy_connect_response(char* buf, int len);

    void on_client_read(char* buf, int len);
    void on_remote_read(char* buf, int len);
    
    // The core function to gracefully close the session.
    void close_session();

    enum State {
        INITIAL,
        CONNECTING,
        AWAITING_CONNECT_RESPONSE,
        ESTABLISHED,
        CLOSING
    };

    std::atomic<State> m_state;
    SOCKET m_client_socket;
    SOCKET m_remote_socket;
    OriginalDestination m_original_dest;

    std::vector<uint8_t> m_initial_buffer; // Buffer for data received before ESTABLISHED
    
    std::string m_detected_domain;
    bool m_is_direct;
};
