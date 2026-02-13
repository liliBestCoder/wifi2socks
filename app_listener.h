#pragma once

#include <string>
#include <thread>
#include <atomic>

class AppListener {
public:
    static AppListener& instance();

    AppListener(const AppListener&) = delete;
    AppListener& operator=(const AppListener&) = delete;

    // Starts the TCP and UDP listeners.
    void start(const std::string& host, uint16_t port);

    // Stops the listeners.
    void stop();

    void* get_udp_socket() const;

private:
    AppListener();
    ~AppListener();

    void tcp_listener_thread();
    void udp_listener_thread();

    std::string m_host;
    uint16_t m_port;

    std::atomic<bool> m_running;
    std::thread m_tcp_thread;
    std::thread m_udp_thread;

    // Sockets are defined in the .cpp file to avoid including winsock2.h here
    void* m_tcp_socket;
    void* m_udp_socket;
};

