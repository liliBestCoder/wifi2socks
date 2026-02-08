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

LogLevel g_log_level = LOG_LEVEL_DEBUG;

#include "winpkfilter_driver.h"
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
                        // 修正为 \Device\ 格式
                        return "\\Device\\" + name;
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

    // 禁用 GeoChecker
    LOG_INFO("[CORE] GeoChecker Disabled by user request.");

    std::string adapter_name = find_adapter_by_ip(g_config.tap_ip);
    static WinPkFilterDriver pk_driver;
    set_winpkfilter_driver(&pk_driver);
    
    WinPkFilterDriver::PacketHandler handler = [](const char* packet, size_t length, bool outbound) {
        std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
        process_ethernet_frame(packet, length, outbound);
    };

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
        pk_driver.start(adapter_name, handler);
    }

    struct tcp_pcb* pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, g_config.lwip_listen_port);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, tcp_proxy_accept);

    SimpleHttpServer::instance().start(g_config.http_api_port);

    while (true) {
        MainDispatcher::instance().process_pending();
        {
            std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
            sys_check_timeouts();
        }
        udp_check_timeouts();
        NatTable::instance().cleanup(300000); 
        WiFiAPManager::instance().CheckKeepAlive();
        Sleep(50); 
    }
    return 0;
}
