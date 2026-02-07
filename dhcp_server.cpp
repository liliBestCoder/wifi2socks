#include "dhcp_server.h"
#include "logger.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <cstdint>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// DHCP Message Structure (simplified)
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
    inet_pton(AF_INET, listen_ip_.c_str(), &server_addr.sin_addr);
    server_addr.sin_port = htons(listen_port_);

    if (bind(sock_, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        LOG_ERROR("Failed to bind socket to %s:%d. Error: %d", listen_ip_.c_str(), listen_port_, WSAGetLastError());
        closesocket(sock_);
        WSACleanup();
        return false;
    }

    running_ = true;
    worker_thread_ = std::thread(&DhcpServer::run, this);
    LOG_INFO("DHCP server started on %s:%d", listen_ip_.c_str(), listen_port_);
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

// Very basic DHCP message handling
void DhcpServer::handle_request(const char* buffer, int size, const sockaddr_in& client_addr) {
    if (size < sizeof(DHCP_Message)) {
        return;
    }
    auto* msg = (DHCP_Message*)buffer;

    if (msg->op != 1) { // 1 = BOOTREQUEST
        return;
    }

    uint8_t dhcp_message_type = 0;
    uint8_t* options = msg->options;
    
    // Magic cookie
    if (memcmp(options, "\x63\x82\x53\x63", 4) != 0) {
        return;
    }
    options += 4;
    int option_len_rem = sizeof(msg->options) - 4;

    // Find DHCP Message Type option
    while (option_len_rem > 0 && *options != 255) {
        uint8_t opt_code = *options++;
        uint8_t opt_len = *options++;
        option_len_rem -= 2;
        if (opt_code == 53) { // DHCP Message Type
            dhcp_message_type = *options;
        }
        options += opt_len;
        option_len_rem -= opt_len;
    }

    if (dhcp_message_type == 1) { // DHCPDISCOVER
        LOG_INFO("DHCPDISCOVER received");
        
        DHCP_Message offer_msg = {0};
        offer_msg.op = 2; // BOOTREPLY
        offer_msg.htype = msg->htype;
        offer_msg.hlen = msg->hlen;
        offer_msg.xid = msg->xid;
        offer_msg.flags = msg->flags;
        memcpy(offer_msg.chaddr, msg->chaddr, 16);
        
        inet_pton(AF_INET, "192.168.137.2", &offer_msg.yiaddr); // Your IP for client
        inet_pton(AF_INET, listen_ip_.c_str(), &offer_msg.siaddr); // Server IP

        uint8_t* offer_options = offer_msg.options;
        memcpy(offer_options, "\x63\x82\x53\x63", 4); // Magic cookie
        offer_options += 4;

        // DHCP Message Type: Offer
        *offer_options++ = 53; *offer_options++ = 1; *offer_options++ = 2; // DHCPOFFER

        // Subnet Mask
        *offer_options++ = 1; *offer_options++ = 4;
        inet_pton(AF_INET, "255.255.255.0", offer_options); offer_options += 4;

        // Router (Gateway)
        *offer_options++ = 3; *offer_options++ = 4;
        inet_pton(AF_INET, listen_ip_.c_str(), offer_options); offer_options += 4;

        // DNS Server
        *offer_options++ = 6; *offer_options++ = 4;
        inet_pton(AF_INET, listen_ip_.c_str(), offer_options); offer_options += 4;
        
        // Lease Time
        *offer_options++ = 51; *offer_options++ = 4;
        uint32_t lease_time = htonl(86400); // 24 hours
        memcpy(offer_options, &lease_time, 4); offer_options += 4;
        
        // End option
        *offer_options++ = 255;

        sockaddr_in broadcast_addr;
        broadcast_addr.sin_family = AF_INET;
        broadcast_addr.sin_port = htons(68);
        broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;

        sendto(sock_, (char*)&offer_msg, sizeof(offer_msg), 0, (sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
        LOG_INFO("DHCPOFFER sent");

    } else if (dhcp_message_type == 3) { // DHCPREQUEST
        LOG_INFO("DHCPREQUEST received");

        DHCP_Message ack_msg = {0};
        ack_msg.op = 2; // BOOTREPLY
        ack_msg.htype = msg->htype;
        ack_msg.hlen = msg->hlen;
        ack_msg.xid = msg->xid;
        ack_msg.flags = msg->flags;
        memcpy(ack_msg.chaddr, msg->chaddr, 16);

        inet_pton(AF_INET, "192.168.137.2", &ack_msg.yiaddr); // Your IP for client
        inet_pton(AF_INET, listen_ip_.c_str(), &ack_msg.siaddr); // Server IP

        uint8_t* ack_options = ack_msg.options;
        memcpy(ack_options, "\x63\x82\x53\x63", 4); // Magic cookie
        ack_options += 4;

        // DHCP Message Type: Ack
        *ack_options++ = 53; *ack_options++ = 1; *ack_options++ = 5; // DHCPACK

        // Subnet Mask
        *ack_options++ = 1; *ack_options++ = 4;
        inet_pton(AF_INET, "255.255.255.0", ack_options); ack_options += 4;

        // Router (Gateway)
        *ack_options++ = 3; *ack_options++ = 4;
        inet_pton(AF_INET, listen_ip_.c_str(), ack_options); ack_options += 4;

        // DNS Server
        *ack_options++ = 6; *ack_options++ = 4;
        inet_pton(AF_INET, listen_ip_.c_str(), ack_options); ack_options += 4;

        // Lease Time
        *ack_options++ = 51; *ack_options++ = 4;
        uint32_t lease_time = htonl(86400); // 24 hours
        memcpy(ack_options, &lease_time, 4); ack_options += 4;

        // End option
        *ack_options++ = 255;

        sockaddr_in broadcast_addr;
        broadcast_addr.sin_family = AF_INET;
        broadcast_addr.sin_port = htons(68);
        broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;

        sendto(sock_, (char*)&ack_msg, sizeof(ack_msg), 0, (sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
        LOG_INFO("DHCPACK sent");
    }
}
