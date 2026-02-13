#include "proxy_tcp.h"
#include "logger.h"
#include "rule_manager.h"
#include "tls_parser.h"
#include "geo_checker.h"
#include "main_dispatcher.h"
#include "traffic_manager.h"

#include <mswsock.h>
#include <vector>

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
    m_worker = WorkerPool::instance().get_worker();
    if (!m_worker) {
        LOG_ERROR("[ProxyTCP] No available workers. Closing session.");
        close_session();
        return;
    }

    // Add client socket to IOCP for initial read
    retain(); // Increment ref count for the client socket
    m_worker->add_socket(
        m_client_socket,
        this,
        [this](char* buf, int len) { on_client_initial_read(buf, len); },
        nullptr, // No write callback initially
        [this]() { on_close(); }
    );
    // Request the first read
    m_worker->read_async(m_client_socket);
}

void ProxyTCP::on_client_initial_read(char* buf, int len) {
    if (len <= 0) {
        close_session();
        return;
    }

    m_initial_buffer.insert(m_initial_buffer.end(), buf, buf + len);

    // Try to parse for domain
    m_detected_domain = TlsParser::parse_client_hello((const char*)m_initial_buffer.data(), m_initial_buffer.size());
    if (m_detected_domain.empty()) {
        // Fallback or handle non-TLS protocols if necessary
        // For now, we assume we need a domain to make a routing decision.
        // If domain is not found after a certain amount of data, we might need to decide based on IP.
        LOG_DEBUG("[ProxyTCP] Domain not found yet, need more data.");
        m_worker->read_async(m_client_socket); // Read more
        return;
    }
    
    LOG_INFO("[ProxyTCP] Detected domain: %s", m_detected_domain.c_str());

    // Routing decision
    Rule rule = RuleManager::instance().match(m_detected_domain);
    m_is_direct = (rule == RULE_DIRECT);

    // Switch client socket's read callback to forwarding mode
    m_worker->update_read_callback(m_client_socket, [this](char* buf, int len) { on_client_read(buf, len); });
    
    // Now that we have the domain, connect to the remote
    connect_remote();
}

void ProxyTCP::connect_remote() {
    m_state = CONNECTING;

    sockaddr_in remote_addr;
    remote_addr.sin_family = AF_INET;

    if (m_is_direct) {
        LOG_INFO("[ProxyTCP] Routing DIRECT for domain %s", m_detected_domain.c_str());
        // For direct connection, we use the original destination IP and Port
        remote_addr.sin_addr.s_addr = m_original_dest.ip;
        remote_addr.sin_port = m_original_dest.port;
    } else {
        LOG_INFO("[ProxyTCP] Routing PROXY for domain %s", m_detected_domain.c_str());
        // For proxy connection, resolve the proxy server address
        // This part needs your proxy server logic (e.g., from config)
        // For now, placeholder:
        inet_pton(AF_INET, g_config.proxy_server_ip.c_str(), &remote_addr.sin_addr);
        remote_addr.sin_port = htons(g_config.proxy_server_port);
    }
    
    m_remote_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    u_long mode = 1;
    ioctlsocket(m_remote_socket, FIONBIO, &mode);
    
    // Bind the socket to a local address before connecting
    sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;
    bind(m_remote_socket, (SOCKADDR*)&bind_addr, sizeof(bind_addr));

    retain(); // Increment ref count for the remote socket
    m_worker->add_socket(
        m_remote_socket,
        this,
        [this](char* buf, int len) { on_remote_read(buf, len); },
        [this](int len) { on_remote_write(len); },
        [this]() { on_close(); }
    );

    auto connect_ex = get_connect_ex();
    if (!connect_ex) {
        LOG_ERROR("[ProxyTCP] Failed to get ConnectEx pointer.");
        close_session();
        return;
    }

    // Use ConnectEx for asynchronous connection
    if (!connect_ex(m_remote_socket, (SOCKADDR*)&remote_addr, sizeof(remote_addr), NULL, 0, NULL, m_worker->get_overlapped_for_connect(m_remote_socket))) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            LOG_ERROR("[ProxyTCP] ConnectEx failed with error: %d", WSAGetLastError());
            close_session();
        }
    }
    // The result of the connection will be delivered via the Worker's IOCP loop,
    // which will then call on_remote_connect.
}

void ProxyTCP::on_remote_connect() {
    LOG_DEBUG("[ProxyTCP] Remote connection established.");
    m_state = ESTABLISHED;
    
    // Update socket context after connection
    setsockopt(m_remote_socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);

    // Start reading from the remote end
    m_worker->read_async(m_remote_socket);

    // Send the buffered initial data to the remote
    if (!m_initial_buffer.empty()) {
        TrafficManager::instance().report_proxy_tx(m_initial_buffer.size(), m_is_direct);
        m_remote_write_busy = true;
        m_worker->write_async(m_remote_socket, (char*)m_initial_buffer.data(), m_initial_buffer.size());
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
    // Potentially read more from remote if it was paused
}

void ProxyTCP::on_remote_write(int len) {
    m_remote_write_busy = false;
    // After sending the initial buffer, start reading from the client
    if (m_state == ESTABLISHED) {
        m_worker->read_async(m_client_socket);
    }
}

void ProxyTCP::on_close() {
    // A socket has been closed (either by peer or by us).
    // This will trigger the release() call, and when both sockets are closed,
    // the object will be deleted.
    release();
}

void ProxyTCP::close_session() {
    if (m_state == CLOSING) return;
    m_state = CLOSING;

    LOG_DEBUG("[ProxyTCP] Closing session.");

    // This will cause the on_close callbacks to be triggered if they haven't already.
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
        // Post a task to the main dispatcher to delete this object safely.
        // This avoids deleting the object from within its own method call stack.
        MainDispatcher::instance().queue_task([self = shared_from_this()]() {
            // The object is deleted when `self` goes out of scope.
        });
    }
}