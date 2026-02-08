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

    // Directly handle a request buffer (e.g. from WinDivert)
    void handle_request(const char* buffer, int size, const sockaddr_in& client_addr);

private:
    void run();

    std::string listen_ip_;
    int listen_port_;
    SOCKET sock_;
    bool running_;
    std::thread worker_thread_;
};
