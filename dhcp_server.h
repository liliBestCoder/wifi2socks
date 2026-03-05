#pragma once

#include <string>
#include <vector>
#include <thread>
#include <map>
#include <chrono>
#include <mutex>
#include <WinSock2.h>

struct DhcpResponse {
    std::vector<uint8_t> data; // ��Ӧ��
    int length = 0;             // ʵ�ʳ���
    uint32_t client_ip = 0;     // ��ѡ���ͻ��� IP
};

class DhcpServer {

public:
    DhcpServer(const std::string& listen_ip, int listen_port = 67);
    ~DhcpServer();

    bool start();
    void stop();

    // Directly handle a request buffer (e.g. from WinDivert)
    DhcpResponse handle_request_buffer(const char* buffer, int size);
    void handle_request(const char* buffer, int size, const sockaddr_in& client_addr);
    uint32_t find_available_ip(const std::vector<uint8_t>& mac);
    uint32_t get_requested_ip(const char* buffer);
    bool get_mac_by_ip(uint32_t ip, uint8_t* mac);

private:
    void run();
    void init_pool();
    std::vector<uint8_t> get_mac_address(const char* buffer);
    uint32_t allocate_ip_locked(const std::vector<uint8_t>& mac);

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
