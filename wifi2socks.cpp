#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "iphlpapi.lib")

#include "app_config.h"

LogLevel g_log_level = LOG_LEVEL_INFO;

#include "winpkfilter_driver.h"
#include "packet_pool.h"
#include "dhcp_server.h"
#include "worker.h"
#include "lwip/etharp.h"
#include "lwip/ip.h"
#include "lwip_handler.h"
#include "proxy_tcp.h"
#include "proxy_udp.h"
#include "main_dispatcher.h"
#include "nat_table.h"
#include "geo_checker.h"
#include "config_loader.h"
#include <iostream>
#include <thread>
#include <shellapi.h>

#include "traffic_manager.h"
#include "http_server.h"
#include "wifi_ap.h"
#include "wifi_ap_listener.h"

DhcpServer* g_dhcp_server_ptr = nullptr;

std::string find_adapter_by_ip(const std::string& target_ip) {
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    ULONG outBufLen = 15000;
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    
    LOG_INFO("[CORE] Searching for NDIS adapter with IP: %s", target_ip.c_str());

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen) == ERROR_SUCCESS) {
        for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != nullptr; pCurr = pCurr->Next) {
            for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurr->FirstUnicastAddress; pUnicast != nullptr; pUnicast = pUnicast->Next) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* sa_in = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ip_str, INET_ADDRSTRLEN);
                    if (target_ip == ip_str) {
                        std::string name = pCurr->AdapterName;
                        LOG_INFO("MATCH FOUND BY IP: %s", name.c_str());
                        free(pAddresses);
                        // 修正为 \\Device\\ 格式
                        return "\\\\Device\\\\" + name;
                    }
                }
            }
        }
    }
    
    if (pAddresses) free(pAddresses);
    return "";
}

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    // Increase process and thread priority for better performance
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    Microsoft::WRL::Wrappers::RoInitializeWrapper initialize(RO_INIT_MULTITHREADED);
    if (FAILED(initialize)) return 1;

    load_config("config.ini");

    static Wifi2SocksWiFiListener wifi_listener;
    try {
        std::wstring ssid(g_config.wifi_ssid.begin(), g_config.wifi_ssid.end());
        std::wstring pass(g_config.wifi_password.begin(), g_config.wifi_password.end());
        WiFiAPManager::instance().SetSSID(ssid);
        WiFiAPManager::instance().SetPassphrase(pass);
        WiFiAPManager::instance().RegisterListener(&wifi_listener);
        WiFiAPManager::instance().Start();
        LOG_INFO("[CORE] WiFi AP Started.");
    } catch (...) {}
    
    static DhcpServer dhcp_server(g_config.tap_ip);
    g_dhcp_server_ptr = &dhcp_server;
    dhcp_server.start();

    TrafficManager::instance().start();

    GeoChecker::instance().init();
    LOG_INFO("[CORE] GeoChecker Initialized.");

    std::string adapter_name = find_adapter_by_ip(g_config.tap_ip);
    static WinPkFilterDriver pk_driver;
    set_winpkfilter_driver(&pk_driver);
    
    PacketPool::instance().init(8192);
    WorkerPool::instance().init(8);
    lwip_init();

    ip4_addr_t ip, mask, gw;
    ip4addr_aton(g_config.tap_ip.c_str(), &ip);
    ip4addr_aton(g_config.tap_netmask.c_str(), &mask); 
    ip4addr_aton("0.0.0.0", &gw); 

    netif_add(&g_netif, &ip, &mask, &gw, NULL, netif_init_cb, ethernet_input);
    netif_set_default(&g_netif);
    
    if (!adapter_name.empty()) {
        if (pk_driver.get_adapter_mac(adapter_name, g_netif.hwaddr)) {
             LOG_INFO("[CORE] LwIP MAC set to %02X:%02X:%02X:%02X:%02X:%02X", 
                 g_netif.hwaddr[0], g_netif.hwaddr[1], g_netif.hwaddr[2], 
                 g_netif.hwaddr[3], g_netif.hwaddr[4], g_netif.hwaddr[5]);
        } else {
             LOG_ERROR("[CORE] Failed to find MAC for adapter %s", adapter_name.c_str());
        }
    }
    
    netif_set_up(&g_netif);
    netif_set_link_up(&g_netif);

    if (!adapter_name.empty()) {
        if (!pk_driver.start_batch(adapter_name, [](std::vector<WinPkFilterDriver::Packet>&& packets) {
            std::vector<WinPkFilterDriver::Packet> inbound_pkts;
            inbound_pkts.reserve(packets.size());

            for (auto& p : packets) {
                if (p.outbound) {
                    // 出站包（来自宿主机协议栈）在驱动线程立即处理并转发
                    // 避免排队延迟，且出站路径不触及 LwIP 状态，是线程安全的
                    process_ethernet_frame((const char*)p.data->data, p.data->length, true);
                } else {
                    // 入站包（来自手机/客户端）收集起来批量交给主线程处理
                    inbound_pkts.push_back(std::move(p));
                }
            }

            if (!inbound_pkts.empty()) {
                MainDispatcher::instance().queue_task([pkts = std::move(inbound_pkts)]() {
                    for (const auto& p : pkts) {
                        process_ethernet_frame((const char*)p.data->data, p.data->length, false);
                    }
                });
            }
        })) {
            LOG_ERROR("[CORE] Failed to start WinPkFilter driver in batch mode.");
        }
    }

    struct tcp_pcb* pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, g_config.lwip_listen_port);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, tcp_proxy_accept);

    SimpleHttpServer::instance().start(g_config.http_api_port);

    uint64_t last_cleanup = 0;
    uint64_t last_keepalive = 0;
    uint64_t last_stats = 0;
    size_t peak_q_size = 0;

    while (true) {
        // Monitor peak queue size BEFORE processing
        size_t current_q_size = MainDispatcher::instance().get_queue_size();
        if (current_q_size > peak_q_size) {
            peak_q_size = current_q_size;
        }

        // All LwIP calls happen here in the Main thread, no lock needed.
        MainDispatcher::instance().process_pending();
        sys_check_timeouts();
        udp_check_timeouts();

        flush_outbound_packets();

        uint64_t now = GetTickCount64();

        // Report stats every 1 second
        if (now - last_stats > 1000) {
            if (peak_q_size > 0) {
                LOG_INFO("[CORE] Main thread queue peak size (last 1s): %llu", (unsigned long long)peak_q_size);
                peak_q_size = 0; 
            }
            last_stats = now;
        }

        // Cleanup NAT table every 10 seconds
        if (now - last_cleanup > 10000) {
            NatTable::instance().cleanup(300000); 
            last_cleanup = now;
        }
        // Check WiFi KeepAlive every 1 second
        if (now - last_keepalive > 1000) {
            WiFiAPManager::instance().CheckKeepAlive();
            last_keepalive = now;
        }

        // Wait for tasks or 1ms timeout. 
        WaitForSingleObject(MainDispatcher::instance().get_event_handle(), 1);
    }
    return 0;
}