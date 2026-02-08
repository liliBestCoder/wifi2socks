#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include "dhcp_server.h"
#include "app_config.h"
#include "logger.h"
#include <iphlpapi.h>
#include <cstring>
#include <cstdint>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// DHCP Message Structure (simplified)
#pragma pack(push, 1) 
struct DHCP_Message {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[312];
};
#pragma pack(pop) 

DhcpServer::DhcpServer(const std::string& listen_ip, int listen_port)
    : listen_ip_(listen_ip), listen_port_(listen_port), sock_(INVALID_SOCKET), running_(false) {}

DhcpServer::~DhcpServer() {
    stop();
}

bool DhcpServer::start() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERROR("WSAStartup failed");
        return false;
    }

    sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_ == INVALID_SOCKET) {
        LOG_ERROR("Failed to create socket");
        WSACleanup();
        return false;
    }

    int broadcast = 1;
    if (setsockopt(sock_, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast)) == SOCKET_ERROR) {
        LOG_ERROR("setsockopt for SO_BROADCAST failed");
        closesocket(sock_);
        WSACleanup();
        return false;
    }
    
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, g_config.tap_ip.c_str(), &server_addr.sin_addr);
    server_addr.sin_port = htons(listen_port_);

    if (bind(sock_, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        LOG_ERROR("Failed to bind DHCP socket to %s:%d. Error: %d", g_config.tap_ip.c_str(), listen_port_, WSAGetLastError());
        closesocket(sock_);
        WSACleanup();
        return false;
    }

    running_ = true;
    worker_thread_ = std::thread(&DhcpServer::run, this);
    LOG_INFO("DHCP server started on port %d (Gateway: %s)", listen_port_, g_config.tap_ip.c_str());
    return true;
}

void DhcpServer::stop() {
    running_ = false;
    if (sock_ != INVALID_SOCKET) {
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    WSACleanup();
    LOG_INFO("DHCP server stopped");
}

void DhcpServer::run() {
    char buffer[1500];
    sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);

    while (running_) {
        int recv_len = recvfrom(sock_, buffer, sizeof(buffer), 0, (sockaddr*)&client_addr, &client_addr_len);
        if (recv_len == SOCKET_ERROR) {
            if (running_) {
                LOG_ERROR("recvfrom failed with error: %d", WSAGetLastError());
            }
            continue;
        }
        handle_request(buffer, recv_len, client_addr);
    }
}

void DhcpServer::handle_request(const char* buffer, int size, const sockaddr_in& client_addr) {
    if (size < 240) return;
    auto* msg = (DHCP_Message*)buffer;
    if (msg->op != 1) return;

    uint8_t dhcp_message_type = 0;
    uint8_t* options = msg->options;
    if (memcmp(options, "\x63\x82\x53\x63", 4) != 0) return;
    
    options += 4;
    int option_len_rem = sizeof(msg->options) - 4;
    while (option_len_rem > 0 && *options != 255) {
        uint8_t opt_code = *options++;
        uint8_t opt_len = *options++;
        option_len_rem -= 2;
        if (opt_code == 53) {
            dhcp_message_type = *options;
        }
        options += opt_len;
        option_len_rem -= opt_len;
    }

    // Standard IP calculation using ntohl/htonl to avoid endian issues
    uint32_t server_ip_n;
    inet_pton(AF_INET, g_config.tap_ip.c_str(), &server_ip_n);
    
    uint32_t server_ip_h = ntohl(server_ip_n);
    uint32_t client_ip_h = (server_ip_h & 0xFFFFFF00) | 3; // Force .2
    uint32_t client_ip_n = htonl(client_ip_h);

    if (dhcp_message_type == 1 || dhcp_message_type == 3) { 
        bool is_discover = (dhcp_message_type == 1);
        
        DHCP_Message resp_msg = {0};
        resp_msg.op = 2; 
        resp_msg.htype = msg->htype;
        resp_msg.hlen = msg->hlen;
        resp_msg.xid = msg->xid;
        resp_msg.flags = msg->flags;
        memcpy(resp_msg.chaddr, msg->chaddr, 16);
        
        resp_msg.yiaddr = client_ip_n;
        resp_msg.siaddr = server_ip_n;

        uint8_t* resp_options = resp_msg.options;
        memcpy(resp_options, "\x63\x82\x53\x63", 4); 
        resp_options += 4;

        *resp_options++ = 53; *resp_options++ = 1; 
        *resp_options++ = is_discover ? 2 : 5; 

        *resp_options++ = 1; *resp_options++ = 4; // Mask
        inet_pton(AF_INET, "255.255.255.0", resp_options); resp_options += 4;

        *resp_options++ = 3; *resp_options++ = 4; // Router
        memcpy(resp_options, &server_ip_n, 4); resp_options += 4;

        *resp_options++ = 6; *resp_options++ = 4; // DNS
        memcpy(resp_options, &server_ip_n, 4); resp_options += 4;

        *resp_options++ = 54; *resp_options++ = 4; // Server ID
        memcpy(resp_options, &server_ip_n, 4); resp_options += 4;

        *resp_options++ = 51; *resp_options++ = 4; // Lease
        uint32_t lease_time = htonl(86400); memcpy(resp_options, &lease_time, 4); resp_options += 4;

        *resp_options++ = 255; 

        sockaddr_in broadcast_addr;
        broadcast_addr.sin_family = AF_INET;
        broadcast_addr.sin_port = htons(68);
        broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock_, (char*)&resp_msg, sizeof(resp_msg), 0, (sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
        
        char cip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_ip_n, cip_str, INET_ADDRSTRLEN);
        LOG_INFO("DHCP %s: Assigned %s via Gateway %s to %02x:%02x:%02x:%02x:%02x:%02x", 
            is_discover ? "OFFER" : "ACK", cip_str, g_config.tap_ip.c_str(),
            msg->chaddr[0], msg->chaddr[1], msg->chaddr[2], msg->chaddr[3], msg->chaddr[4], msg->chaddr[5]);
    }
}