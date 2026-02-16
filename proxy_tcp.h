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
    
    std::string m_detected_domain;
    bool m_is_direct;

    void try_send(SOCKET socket);
    void on_write_complete(SOCKET socket, int len);

    // Client -> Remote data flow
    std::deque<std::shared_ptr<std::vector<char>>> m_client_send_queue;
    std::atomic<bool> m_client_write_in_progress{false};
    std::mutex m_client_queue_mutex;

    // Remote -> Client data flow
    std::deque<std::shared_ptr<std::vector<char>>> m_remote_send_queue;
    std::atomic<bool> m_remote_write_in_progress{false};
    std::mutex m_remote_queue_mutex;

    // Backpressure Control
    static const size_t HIGH_WATER_MARK = 8 * 1024 * 1024; // 8MB
    static const size_t LOW_WATER_MARK = 2 * 1024 * 1024;  // 2MB
    std::atomic<bool> m_client_read_paused{false};
    std::atomic<bool> m_remote_read_paused{false};
    std::atomic<size_t> m_client_send_queue_size{0};
    std::atomic<size_t> m_remote_send_queue_size{0};
};
