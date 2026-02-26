#pragma once

#include <string>
#include <vector>
#include <thread>
#include <map>
#include <chrono>
#include <mutex>
#include <WinSock2.h>

struct DhcpResponse {
    std::vector<uint8_t> data; // 响应包
    int length = 0;             // 实际长度
    uint32_t client_ip = 0;     // 可选：客户端 IP
};

class DhcpServer {

public:
    DhcpServer(const std::string& listen_ip, int listen_port = 67);
    ~DhcpServer();

    bool start();
    void stop();

    // Directly handle a request buffer (e.g. from WinDivert)
    void handle_request(const char* buffer, int size, const sockaddr_in& client_addr);
    DhcpResponse handle_request_buffer(const char* buffer, int size);

private:
    void run();
    void init_pool();
    std::vector<uint8_t> get_mac_address(const char* buffer);
    uint32_t find_available_ip(const std::vector<uint8_t>& mac);
    uint32_t get_requested_ip(const char* buffer);

    struct Lease {
        uint32_t ip;
        std::chrono::steady_clock::time_point expires;
    };

    std::string listen_ip_;
    int listen_port_;
    SOCKET sock_;
    bool running_;
    std::thread worker_thread_;
    
    std::mutex mtx_;
    std::vector<uint32_t> ip_pool_;
    std::map<std::vector<uint8_t>, Lease> leases_;
    std::chrono::seconds lease_duration_;
};
