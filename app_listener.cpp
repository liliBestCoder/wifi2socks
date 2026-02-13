#include "app_listener.h"
#include "logger.h"
#include "nat_manager.h"
#include "worker.h"
#include "proxy_tcp.h"
#include "proxy_udp.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

AppListener& AppListener::instance() {
    static AppListener inst;
    return inst;
}

AppListener::AppListener() : m_running(false), m_tcp_socket(INVALID_SOCKET), m_udp_socket(INVALID_SOCKET) {}

AppListener::~AppListener() {
    stop();
}

void* AppListener::get_udp_socket() const {
    return m_udp_socket;
}

void AppListener::start(const std::string& host, uint16_t port) {
    if (m_running) {
        return;
    }

    m_host = host;
    m_port = port;
    m_running = true;

    // Start TCP Listener
    m_tcp_thread = std::thread(&AppListener::tcp_listener_thread, this);
    // Start UDP Listener
    m_udp_thread = std::thread(&AppListener::udp_listener_thread, this);

    LOG_INFO("[AppListener] Started listening on %s:%d", host.c_str(), port);
}

void AppListener::stop() {
    if (!m_running) {
        return;
    }
    m_running = false;

    // Close sockets to unblock listener threads
    if (m_tcp_socket != INVALID_SOCKET) {
        closesocket((SOCKET)m_tcp_socket);
        m_tcp_socket = INVALID_SOCKET;
    }
    if (m_udp_socket != INVALID_SOCKET) {
        closesocket((SOCKET)m_udp_socket);
        m_udp_socket = INVALID_SOCKET;
    }

    if (m_tcp_thread.joinable()) {
        m_tcp_thread.join();
    }
    if (m_udp_thread.joinable()) {
        m_udp_thread.join();
    }
    LOG_INFO("[AppListener] Stopped.");
}

void AppListener::tcp_listener_thread() {
    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        LOG_ERROR("[AppListener] Failed to create TCP socket: %d", WSAGetLastError());
        return;
    }
    m_tcp_socket = (void*)listen_socket;

    sockaddr_in service;
    service.sin_family = AF_INET;
    inet_pton(AF_INET, m_host.c_str(), &service.sin_addr);
    service.sin_port = htons(m_port);

    if (bind(listen_socket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        LOG_ERROR("[AppListener] TCP bind failed: %d", WSAGetLastError());
        closesocket(listen_socket);
        return;
    }

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        LOG_ERROR("[AppListener] TCP listen failed: %d", WSAGetLastError());
        closesocket(listen_socket);
        return;
    }

    LOG_INFO("[AppListener] TCP listener is running.");

    while (m_running) {
        sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);
        SOCKET client_socket = accept(listen_socket, (SOCKADDR*)&client_addr, &client_addr_len);

        if (client_socket == INVALID_SOCKET) {
            if (m_running) {
                LOG_ERROR("[AppListener] TCP accept failed: %d", WSAGetLastError());
            }
            continue;
        }

        LOG_DEBUG("[AppListener] Accepted new TCP connection from %s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Find original destination from NAT manager
        ClientKey key;
        key.ip = client_addr.sin_addr.s_addr;
        key.port = client_addr.sin_port;
        
        auto dest = NatManager::instance().get_mapping(key);

        if (dest) {
            // Create a new ProxyTCP session and start it.
            // The session will manage its own lifetime.
            std::make_shared<ProxyTCP>(client_socket, *dest)->start();
        } else {
            LOG_WARN("[AppListener] No NAT mapping found for TCP connection from %s:%d. Closing.", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            closesocket(client_socket);
        }
    }

    closesocket(listen_socket);
    LOG_INFO("[AppListener] TCP listener thread finished.");
}

void AppListener::udp_listener_thread() {
    SOCKET listen_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (listen_socket == INVALID_SOCKET) {
        LOG_ERROR("[AppListener] Failed to create UDP socket: %d", WSAGetLastError());
        return;
    }
    m_udp_socket = (void*)listen_socket;

    sockaddr_in service;
    service.sin_family = AF_INET;
    inet_pton(AF_INET, m_host.c_str(), &service.sin_addr);
    service.sin_port = htons(m_port);

    if (bind(listen_socket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        LOG_ERROR("[AppListener] UDP bind failed: %d", WSAGetLastError());
        closesocket(listen_socket);
        return;
    }
    
    LOG_INFO("[AppListener] UDP listener is running.");

    char* buffer = new char[4096];

    while (m_running) {
        sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);

        int bytes_read = recvfrom(listen_socket, buffer, 4096, 0, (SOCKADDR*)&client_addr, &client_addr_len);

        if (bytes_read == SOCKET_ERROR) {
            if (m_running) {
                LOG_ERROR("[AppListener] UDP recvfrom failed: %d", WSAGetLastError());
            }
            continue;
        }

        // Find original destination
        ClientKey key;
        key.ip = client_addr.sin_addr.s_addr;
        key.port = client_addr.sin_port;

        auto dest = NatManager::instance().get_mapping(key);

        if (dest) {
            // Pass the data to the UDP proxy handler.
            // The handler will manage sending the data to the real destination
            // and routing the response back.
            UdpProxy::handle_client_data(listen_socket, buffer, bytes_read, &client_addr, &(*dest));

        } else {
             LOG_WARN("[AppListener] No NAT mapping for UDP packet from %s:%d.", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        }
    }
    
    delete[] buffer;
    closesocket(listen_socket);
    LOG_INFO("[AppListener] UDP listener thread finished.");
}
