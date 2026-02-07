#pragma once

#include <string>
#include <vector>
#include <thread>
#include <WinSock2.h>

class DhcpServer {
public:
    DhcpServer(const std::string& listen_ip, int listen_port = 67);
    ~DhcpServer();

    bool start();
    void stop();

private:
    void run();
    void handle_request(const char* buffer, int size, const sockaddr_in& client_addr);

    std::string listen_ip_;
    int listen_port_;
    SOCKET sock_;
    bool running_;
    std::thread worker_thread_;
};
