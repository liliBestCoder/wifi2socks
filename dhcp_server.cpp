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
#include <algorithm>

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
    : listen_ip_(listen_ip), listen_port_(listen_port), sock_(INVALID_SOCKET), 
      running_(false), lease_duration_(std::chrono::hours(24)) {}

DhcpServer::~DhcpServer() {
    stop();
}

void DhcpServer::init_pool() {
    uint32_t server_ip_n;
    inet_pton(AF_INET, g_config.tap_ip.c_str(), &server_ip_n);
    uint32_t server_ip_h = ntohl(server_ip_n);
    
    // Create a pool of 100 addresses, e.g., from .100 to .199
    uint32_t subnet = server_ip_h & 0xFFFFFF00;
    for (uint32_t i = 100; i < 200; ++i) {
        ip_pool_.push_back(subnet | i);
    }
}

bool DhcpServer::start() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERROR("WSAStartup failed");
        return false;
    }

    init_pool();

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
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
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

std::vector<uint8_t> DhcpServer::get_mac_address(const char* buffer) {
    auto* msg = (DHCP_Message*)buffer;
    return std::vector<uint8_t>(msg->chaddr, msg->chaddr + msg->hlen);
}

uint32_t DhcpServer::get_requested_ip(const char* buffer) {
    auto* msg = (DHCP_Message*)buffer;
    uint8_t* options = msg->options + 4;
    int option_len_rem = sizeof(msg->options) - 4;
    while (option_len_rem > 0 && *options != 255) {
        uint8_t opt_code = *options++;
        uint8_t opt_len = *options++;
        option_len_rem -= 2;
        if (opt_code == 50 && opt_len == 4) { // Option 50: Requested IP Address
            uint32_t requested_ip;
            memcpy(&requested_ip, options, 4);
            return requested_ip;
        }
        options += opt_len;
        option_len_rem -= opt_len;
    }
    return 0;
}

uint32_t DhcpServer::find_available_ip(const std::vector<uint8_t>& mac) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto now = std::chrono::steady_clock::now();

    // 1. Check if this MAC already has a lease
    auto it = leases_.find(mac);
    if (it != leases_.end()) {
        it->second.expires = now + lease_duration_;
        return it->second.ip;
    }

    // 2. Try to find a free IP from the pool
    if (!ip_pool_.empty()) {
        uint32_t ip_h = ip_pool_.back();
        ip_pool_.pop_back();
        leases_[mac] = { ip_h, now + lease_duration_ };
        return ip_h;
    }

    // 3. If pool is empty, try to reclaim an expired lease
    for (auto& pair : leases_) {
        if (pair.second.expires < now) {
            uint32_t expired_ip_h = pair.second.ip;
            leases_.erase(pair.first);
            leases_[mac] = { expired_ip_h, now + lease_duration_ };
            return expired_ip_h;
        }
    }

    return 0; // No IP available
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
        if (opt_code == 53) { // DHCP Message Type
            dhcp_message_type = *options;
        }
        options += opt_len;
        option_len_rem -= opt_len;
    }

    uint32_t yiaddr_h = 0;
    auto mac = get_mac_address(buffer);
    if (mac.empty()) return;
    
    // --- DHCPDISCOVER ---
    if (dhcp_message_type == 1) { 
        yiaddr_h = find_available_ip(mac);
        if (yiaddr_h == 0) {
            LOG_ERROR("No available IP addresses to offer.");
            return;
        }
    // --- DHCPREQUEST ---
    } else if (dhcp_message_type == 3) {
        uint32_t requested_ip_n = get_requested_ip(buffer);
        if (requested_ip_n != 0) { // Client requests a specific IP
             yiaddr_h = ntohl(requested_ip_n);
        } else { // Client is renewing, ciaddr should be used
             yiaddr_h = ntohl(msg->ciaddr);
        }

        std::lock_guard<std::mutex> lock(mtx_);
        auto it = leases_.find(mac);
        if (it != leases_.end() && it->second.ip == yiaddr_h) {
            // This is our client, renew the lease
            it->second.expires = std::chrono::steady_clock::now() + lease_duration_;
        } else {
             // Potentially a new client requesting an IP that might be in our pool
             // Or a client with a very old lease. We re-assign it.
             auto pool_it = std::find(ip_pool_.begin(), ip_pool_.end(), yiaddr_h);
             if (pool_it != ip_pool_.end()) {
                 ip_pool_.erase(pool_it);
             }
             leases_[mac] = { yiaddr_h, std::chrono::steady_clock::now() + lease_duration_ };
        }
    } else {
        return; // We don't handle other types for now
    }
    
    if (yiaddr_h == 0) return;

    DHCP_Message resp_msg = {0};
    resp_msg.op = 2; // BOOTREPLY
    resp_msg.htype = msg->htype;
    resp_msg.hlen = msg->hlen;
    resp_msg.xid = msg->xid;
    resp_msg.flags = msg->flags;
    memcpy(resp_msg.chaddr, msg->chaddr, 16);
    
    uint32_t yiaddr_n = htonl(yiaddr_h);
    resp_msg.yiaddr = yiaddr_n;

    uint32_t server_ip_n;
    inet_pton(AF_INET, g_config.tap_ip.c_str(), &server_ip_n);
    resp_msg.siaddr = server_ip_n;

    uint8_t* resp_options = resp_msg.options;
    memcpy(resp_options, "\x63\x82\x53\x63", 4); 
    resp_options += 4;

    // Option 53: DHCP Message Type
    *resp_options++ = 53; *resp_options++ = 1; 
    *resp_options++ = (dhcp_message_type == 1) ? 2 /*OFFER*/ : 5 /*ACK*/; 

    // Option 1: Subnet Mask
    *resp_options++ = 1; *resp_options++ = 4;
    inet_pton(AF_INET, "255.255.255.0", resp_options); resp_options += 4;

    // Option 3: Router
    *resp_options++ = 3; *resp_options++ = 4;
    memcpy(resp_options, &server_ip_n, 4); resp_options += 4;

    // Option 6: DNS Server
    *resp_options++ = 6; *resp_options++ = 4;
    memcpy(resp_options, &server_ip_n, 4); resp_options += 4;

    // Option 54: Server Identifier
    *resp_options++ = 54; *resp_options++ = 4;
    memcpy(resp_options, &server_ip_n, 4); resp_options += 4;

    // Option 51: IP Address Lease Time
    *resp_options++ = 51; *resp_options++ = 4;
    uint32_t lease_time_n = htonl((uint32_t)lease_duration_.count());
    memcpy(resp_options, &lease_time_n, 4); resp_options += 4;

    // Option 26: Interface MTU (1400 bytes to be safe over proxy/tunnels)
    *resp_options++ = 26; *resp_options++ = 2;
    uint16_t mtu_n = htons(1400);
    memcpy(resp_options, &mtu_n, 2); resp_options += 2;
    
    // Option 255: End
    *resp_options++ = 255; 

    sockaddr_in broadcast_addr;
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(68);
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;
    
    sendto(sock_, (char*)&resp_msg, sizeof(resp_msg), 0, (sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
    
    char cip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &yiaddr_n, cip_str, INET_ADDRSTRLEN);
    
    LOG_INFO("DHCP %s: Assigned %s to %02x:%02x:%02x:%02x:%02x:%02x for %lld seconds", 
        (dhcp_message_type == 1) ? "OFFER" : "ACK", 
        cip_str,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        lease_duration_.count());
}