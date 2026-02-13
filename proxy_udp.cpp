#include "proxy_udp.h"
#include "worker.h"
#include "logger.h"
#include "rule_manager.h"
#include "geo_checker.h"
#include "app_config.h"
#include "traffic_manager.h"
#include "app_listener.h"
#include "proxy_tcp.h"
#include "dns_over_tcp_proxy.h"

#include <unordered_map>
#include <mutex>
#include <memory>
#include <vector>

// A manager to handle all UDP proxy operations.
class UdpProxyManager {
public:
    UdpProxyManager() : m_worker(nullptr) {}

    void initialize() {
        m_worker = WorkerPool::instance().get_worker(); 
        if (!m_worker) {
            LOG_ERROR("[UdpProxy] Could not get a worker for UDP operations.");
        }
    }

    void shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto const& [key, val] : m_remote_sockets) {
            if (val != INVALID_SOCKET) {
                m_worker->remove_socket(val);
            }
        }
        m_remote_sockets.clear();
        m_reverse_routes.clear();
        LOG_INFO("[UdpProxy] Shutdown complete.");
    }

    // Helper to parse domain name from DNS query
    std::string parse_dns_query_domain(const char* data, int len) {
        if (len < 13) return ""; // Basic check for header + qname
        
        std::string domain = "";
        const unsigned char* qname = (const unsigned char*)(data + 12);
        int pos = 0;

        while (pos < (len - 12)) {
            uint8_t label_len = qname[pos];
            if (label_len == 0) {
                break;
            }
            if ((label_len & 0xC0) == 0xC0) { // Pointer
                break; 
            }
            if (pos + 1 + label_len > (len - 12)) {
                return ""; // Malformed packet
            }
            if (!domain.empty()) {
                domain += ".";
            }
            domain.append((const char*)(qname + pos + 1), label_len);
            pos += 1 + label_len;
        }
        return domain;
    }


    void handle_data(SOCKET listener_socket, const char* data, int len, const sockaddr_in* client_addr, const OriginalDestination* dest) {
        if (!m_worker) {
            LOG_WARN("[UdpProxy] Not initialized. Dropping packet.");
            return;
        }

        // --- DNS Handling ---
        if (ntohs(dest->port) == 53) {
            std::string domain = parse_dns_query_domain(data, len);
            if (!domain.empty()) {
                Rule rule = RuleManager::instance().match(domain);
                if (rule == RULE_PROXY) {
                    LOG_INFO("[DNS] Routing DNS query for '%s' over TCP (DoT).", domain.c_str());
                    // This is the hook for DNS-over-TCP
                    // For simplicity, we will create a new TCP proxy session for this.
                    // This is not the most efficient way (could pool TCP connections to proxy), but it's the most straightforward.
                    
                    // The destination for the ProxyTCP is the DNS server we want to use via the proxy.
                    OriginalDestination dot_dest;
                    inet_pton(AF_INET, g_config.proxy_dns_server.c_str(), &dot_dest.ip);
                    dot_dest.port = htons(853); // Standard DoT port

                    // We need a way to get the response back to the UDP client.
                    // We can pass a callback to the ProxyTCP session.
                    auto on_dns_response = [listener_socket, client_addr = *client_addr](const char* dns_resp, int resp_len) {
                        if (resp_len > 0) {
                            sendto(listener_socket, dns_resp, resp_len, 0, (const sockaddr*)&client_addr, sizeof(client_addr));
                        }
                    };
                    
                    // Create and start the one-shot DoT proxy session
                    std::vector<uint8_t> query_vec((uint8_t*)data, (uint8_t*)data + len);
                    std::make_shared<DnsOverTcpProxy>(query_vec, on_dns_response)->start();
                    return; // Done for this packet
                }
            }
        }
        
        // Default: direct UDP forwarding
        sockaddr_in dest_addr_sock = {};
        dest_addr_sock.sin_family = AF_INET;
        dest_addr_sock.sin_addr.s_addr = dest->ip;
        dest_addr_sock.sin_port = dest->port;

        uint64_t dest_key = ((uint64_t)dest->ip << 16) | ntohs(dest->port);

        SOCKET remote_socket = get_or_create_remote_socket(dest_key, client_addr);

        if (remote_socket != INVALID_SOCKET) {
            int bytes_sent = sendto(remote_socket, data, len, 0, (const sockaddr*)&dest_addr_sock, sizeof(dest_addr_sock));
            if (bytes_sent == SOCKET_ERROR) {
                LOG_ERROR("[UdpProxy] sendto to remote failed with error: %d", WSAGetLastError());
            } else {
                 TrafficManager::instance().report_proxy_tx(bytes_sent, true); // Assuming direct for now
            }
        }
    }

private:
    void on_remote_read(SOCKET remote_socket, char* buf, int len, const sockaddr_in* from_addr) {
        if (len <= 0) {
            return;
        }

        TrafficManager::instance().report_proxy_rx(len, true); // Assuming direct

        sockaddr_in client_addr_to_send;
        bool found = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_reverse_routes.find(remote_socket);
            if (it != m_reverse_routes.end()) {
                client_addr_to_send = it->second;
                found = true;
            }
        }

        if (found) {
            SOCKET listener_socket = (SOCKET)AppListener::instance().get_udp_socket();
            if(listener_socket != INVALID_SOCKET) {
                sendto(listener_socket, buf, len, 0, (const sockaddr*)&client_addr_to_send, sizeof(client_addr_to_send));
            }
        } else {
            LOG_WARN("[UdpProxy] Received a UDP packet on a remote socket but could not find a reverse route.");
        }
    }
    
    SOCKET get_or_create_remote_socket(uint64_t dest_key, const sockaddr_in* client_addr) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_remote_sockets.find(dest_key);
        if (it != m_remote_sockets.end()) {
            m_reverse_routes[it->second] = *client_addr;
            return it->second;
        }

        SOCKET new_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (new_socket == INVALID_SOCKET) {
            LOG_ERROR("[UdpProxy] Failed to create remote UDP socket.");
            return INVALID_SOCKET;
        }
        
        u_long mode = 1;
        ioctlsocket(new_socket, FIONBIO, &mode);
        
        m_worker->add_socket(
            new_socket,
            nullptr, 
            [this, new_socket](char* buf, int len, const sockaddr_in* from) { this->on_remote_read(new_socket, buf, len, from); },
            nullptr,
            [this, dest_key]() { 
                std::lock_guard<std::mutex> lock(m_mutex);
                auto it = m_remote_sockets.find(dest_key);
                if (it != m_remote_sockets.end()) {
                    m_reverse_routes.erase(it->second);
                    m_remote_sockets.erase(it);
                }
            }
        );

        m_remote_sockets[dest_key] = new_socket;
        m_reverse_routes[new_socket] = *client_addr;
        
        m_worker->read_from_async(new_socket);

        LOG_DEBUG("[UdpProxy] Created new remote UDP socket for dest key %llu", dest_key);

        return new_socket;
    }

    Worker* m_worker;
    std::mutex m_mutex;
    std::unordered_map<uint64_t, SOCKET> m_remote_sockets;
    std::unordered_map<SOCKET, sockaddr_in> m_reverse_routes;
};

static UdpProxyManager g_udp_manager;

void UdpProxy::initialize() {
    g_udp_manager.initialize();
}

void UdpProxy::shutdown() {
    g_udp_manager.shutdown();
}

void UdpProxy::handle_client_data(SOCKET listener_socket, const char* data, int len, const sockaddr_in* client_addr, const OriginalDestination* dest) {
    g_udp_manager.handle_data(listener_socket, data, len, client_addr, dest);
}
