#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "app_listener.h"
#include "logger.h"
#include "app_config.h"
#include "nat_manager.h"
#include "worker.h"
#include "proxy_tcp.h"
#include "proxy_udp.h"

#pragma comment(lib, "Ws2_32.lib")

AppListener& AppListener::instance() {
    static AppListener inst;
    return inst;
}

AppListener::AppListener() : m_running(false), m_tcp_socket(nullptr), m_udp_socket(nullptr) {}

AppListener::~AppListener() {
    stop();
}

void* AppListener::get_udp_socket() const {
    return m_udp_socket;
}

void AppListener::start(const std::string& host, uint16_t port) {
    if (m_running) return;

    m_host = host;
    m_port = port;
    m_running = true;

    m_tcp_thread = std::thread(&AppListener::tcp_listener_thread, this);
    m_udp_thread = std::thread(&AppListener::udp_listener_thread, this);

    LOG_INFO("[AppListener] Started listening on %s:%d", host.c_str(), port);
}

void AppListener::stop() {
    if (!m_running) return;
    m_running = false;

    if (m_tcp_socket != nullptr) {
        closesocket((SOCKET)m_tcp_socket);
        m_tcp_socket = nullptr;
    }
    if (m_udp_socket != nullptr) {
        closesocket((SOCKET)m_udp_socket);
        m_udp_socket = nullptr;
    }

    if (m_tcp_thread.joinable()) m_tcp_thread.join();
    if (m_udp_thread.joinable()) m_udp_thread.join();
    
    LOG_INFO("[AppListener] Stopped.");
}

void AppListener::tcp_listener_thread() {
    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) return;
    m_tcp_socket = (void*)listen_socket;

    sockaddr_in service;
    service.sin_family = AF_INET;
    inet_pton(AF_INET, m_host.c_str(), &service.sin_addr);
    service.sin_port = htons(m_port);

    if (bind(listen_socket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        closesocket(listen_socket);
        return;
    }

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listen_socket);
        return;
    }

    LOG_INFO("[AppListener] TCP listener is running.");

    while (m_running) {
        sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);
        SOCKET client_socket = accept(listen_socket, (SOCKADDR*)&client_addr, &client_addr_len);

        if (client_socket == INVALID_SOCKET) continue;

        // 优化客户端 socket 性能
        int flag = 1;
        setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag)); // 禁用 Nagle 算法

        // Use correct key generation (Network Byte Order) to match Driver
        uint64_t key = NatManager::make_key(client_addr.sin_addr.s_addr, client_addr.sin_port);
        
        auto dest = NatManager::instance().get_mapping(key);

        if (dest) {
            std::make_shared<ProxyTCP>(client_socket, *dest)->start();
        } else {
            closesocket(client_socket);
        }
    }
    closesocket(listen_socket);
}

void AppListener::udp_listener_thread() {
    SOCKET listen_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (listen_socket == INVALID_SOCKET) return;
    m_udp_socket = (void*)listen_socket;

    sockaddr_in service;
    service.sin_family = AF_INET;
    inet_pton(AF_INET, m_host.c_str(), &service.sin_addr);
    service.sin_port = htons(m_port);

    if (bind(listen_socket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        closesocket(listen_socket);
        return;
    }
    
    LOG_INFO("[AppListener] UDP listener is running.");

    char buffer[65536]; 

    while (m_running) {
        sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);

        int bytes_read = recvfrom(listen_socket, buffer, sizeof(buffer), 0, (SOCKADDR*)&client_addr, &client_addr_len);

        if (bytes_read == SOCKET_ERROR) continue;

        uint64_t key = NatManager::make_key(client_addr.sin_addr.s_addr, client_addr.sin_port);
        auto dest = NatManager::instance().get_mapping(key);

        if (dest) {
            UdpProxy::handle_client_data(listen_socket, buffer, bytes_read, &client_addr, &(*dest));
        }
    }
    closesocket(listen_socket);
}
