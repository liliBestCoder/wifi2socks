#pragma once

#include <winsock2.h>
#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <deque>
#include <mutex>

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

    std::vector<char> m_proxy_response_buffer; // Buffer for proxy CONNECT response
    
    std::vector<uint8_t> m_initial_buffer; // Buffer for data received before ESTABLISHED
    
    std::string m_detected_domain;
    bool m_is_direct;

    void try_send(SOCKET socket);
    void on_write_complete(SOCKET socket, int len);

    // Data flow to Client (from Remote)
    std::deque<std::shared_ptr<std::vector<char>>> m_client_send_queue;
    std::atomic<bool> m_client_write_in_progress{false};
    std::mutex m_client_queue_mutex;

    // Data flow to Remote (from Client)
    std::deque<std::shared_ptr<std::vector<char>>> m_remote_send_queue;
    std::atomic<bool> m_remote_write_in_progress{false};
    std::mutex m_remote_queue_mutex;

    // Graceful closure flags
    std::atomic<bool> m_remote_at_eof{ false };
    std::atomic<bool> m_client_at_eof{ false };

    std::atomic<size_t> m_client_send_queue_size{0};
    std::atomic<size_t> m_remote_send_queue_size{0};
};