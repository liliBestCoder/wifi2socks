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
        WorkerPool::instance().remove_socket((SOCKET)m_tcp_socket);
        m_tcp_socket = nullptr;
    }
    if (m_udp_socket != nullptr) {
        WorkerPool::instance().remove_socket((SOCKET)m_udp_socket);
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

    // Reuse address to avoid "Address already in use" errors on restart
    int reuse = 1;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

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

    LOG_INFO("[AppListener] TCP listener is running using IOCP.");

    // Using IOCP AcceptEx instead of blocking accept loop
    WorkerPool::instance().accept_async(listen_socket, [](SOCKET client_socket, sockaddr_in& client_addr) {
        // This callback is executed in a Worker thread
        
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
    });

    // We don't need a loop here anymore, but the thread should stay alive if needed or we can just return.
    // However, AppListener expects m_tcp_thread to be joinable and potentially running?
    // In the original code, it was a loop. Now it's event driven.
    // Let's keep the thread alive until m_running is false to maintain compatibility with stop().
    while (m_running) {
        Sleep(100);
    }
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
        m_udp_socket = nullptr;
        return;
    }
    
    LOG_INFO("[AppListener] UDP listener is running (IOCP).");

    WorkerPool::instance().add_socket(listen_socket, [this, listen_socket](char* data, int len, sockaddr_in* from) {
        if (len > 0 && from) {
            uint64_t key = NatManager::make_key(from->sin_addr.s_addr, from->sin_port);
            auto dest = NatManager::instance().get_mapping(key);

            if (dest) {
                UdpProxy::handle_client_data(listen_socket, data, len, from, &(*dest));
            }
        }
        
        // Always re-issue the read for the listener socket if still running
        if (m_running) {
            WorkerPool::instance().read_async(listen_socket);
        }
    }, nullptr, true, nullptr, 16); // 16 concurrent reads for the listener

    while (m_running) {
        Sleep(100);
    }
}
