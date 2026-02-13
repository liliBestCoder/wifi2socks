#include "app_listener.h"
#include "logger.h"
#include "nat_manager.h"
#include "worker.h"
#include "proxy_tcp.h" // We'll need to adapt or reuse this
#include "proxy_udp.h"   // We'll need to adapt or reuse this

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
            // We have the original destination, now hand it off to a worker.
            // This part needs to connect to your existing proxy logic.
            // We assume the WorkerPool can handle dispatching a native socket.
            WorkerPool::instance().dispatch_socket(client_socket, *dest);
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
            // We have the original destination, now process the UDP packet.
            // This needs to connect to the existing UDP proxy logic.
            // We'll create a UdpProxy session.
            sockaddr_in dest_addr;
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_addr.s_addr = dest->ip;
            dest_addr.sin_port = dest->port;
            
            // The UdpProxy needs the listening socket to send responses back to the client.
            UdpProxy::handle_client_data(listen_socket, buffer, bytes_read, &client_addr, &dest_addr);

        } else {
             LOG_WARN("[AppListener] No NAT mapping for UDP packet from %s:%d.", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        }
    }
    
    delete[] buffer;
    closesocket(listen_socket);
    LOG_INFO("[AppListener] UDP listener thread finished.");
}
