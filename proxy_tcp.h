#pragma once

#include <winsock2.h>
#include <memory>
#include <vector>
#include <string>

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

    void on_client_read(char* buf, int len);
    void on_remote_read(char* buf, int len);
    
    void on_client_write(int len);
    void on_remote_write(int len);

    void on_close();

    // The core function to gracefully close the session.
    void close_session();

    enum State {
        INITIAL,
        CONNECTING,
        ESTABLISHED,
        CLOSING
    };

    std::atomic<State> m_state;
    SOCKET m_client_socket;
    SOCKET m_remote_socket;
    OriginalDestination m_original_dest;
    Worker* m_worker;

    std::vector<uint8_t> m_initial_buffer; // Buffer for SNI sniffing
    std::string m_detected_domain;
    bool m_is_direct;

    bool m_client_write_busy;
    bool m_remote_write_busy;
    
    // Using a simple reference count to manage the lifetime of the object
    // in relation to the two sockets being in the IOCP loop.
    std::atomic<int> m_ref_count;
    void retain();
    void release();
};