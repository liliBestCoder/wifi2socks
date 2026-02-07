#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#include "app_config.h"

// Global Log Level
LogLevel g_log_level = LOG_LEVEL_INFO;

#include "windivert_driver.h"
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

// Main Entry Point
int main() {
    // 0. Initialize Winsock and WinRT
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    // Initialize WinRT for WiFi
    Microsoft::WRL::Wrappers::RoInitializeWrapper initialize(RO_INIT_MULTITHREADED);
    if (FAILED(initialize)) {
        printf("Failed to initialize Windows Runtime\n");
        return 1;
    }

    // -1. Load Config
    load_config("config.ini");

    // 0. Initialize WiFi AP
    static Wifi2SocksWiFiListener wifi_listener;
    try {
        std::wstring ssid(g_config.wifi_ssid.begin(), g_config.wifi_ssid.end());
        std::wstring pass(g_config.wifi_password.begin(), g_config.wifi_password.end());

        WiFiAPManager::instance().SetSSID(ssid);
        WiFiAPManager::instance().SetPassphrase(pass);
        WiFiAPManager::instance().RegisterListener(&wifi_listener);
        WiFiAPManager::instance().Start();
        LOG_INFO("[CORE] WiFi AP Initialized (SSID: %s).", g_config.wifi_ssid.c_str());
    } catch (const std::exception& e) {
        LOG_ERROR("[CORE] WiFi AP Initialization failed: %s", e.what());
    }
    
    // Start DHCP Server
    static DhcpServer dhcp_server("192.168.11.1");
    dhcp_server.start();

    // -0.5 Start Traffic Manager & HTTP API
    TrafficManager::instance().start();

    // 0.5 Pre-load GeoIP/GeoSite
    try {
        GeoChecker::instance().init();
        LOG_INFO("[CORE] GeoChecker loading in background...");
    } catch (const std::exception& e) {
        LOG_ERROR("[CORE] Warning: GeoChecker failed to load: %s. IP/Domain bypass may not work.", e.what());
    }

    // 1. Initialize WinDivert
    // 使用用户测试成功的原样语法
    static WinDivertDriver divert("ip and ip.SrcAddr >= 192.168.11.0 and ip.SrcAddr <= 192.168.11.255");
    set_windivert_driver(&divert);
    WinDivertDriver::PacketHandler handler = [](const char* packet, size_t length, const WINDIVERT_ADDRESS* addr) {
        std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
        TrafficManager::instance().report_tap_tx(length); // Use same traffic counter
        process_ip_packet(packet, (int)length, addr);
    };
    divert.start(handler);

    // 2. Initialize Worker Pool
    WorkerPool::instance().init(8);
    LOG_INFO("[CORE] Worker Pool Initialized.");

    // 4. Initialize LwIP
    lwip_init();

    ip4_addr_t ip, mask, gw;
    ip4addr_aton("192.168.11.1", &ip);
    ip4addr_aton("255.255.255.0", &mask);
    ip4addr_aton("0.0.0.0", &gw); // No real gateway for this interface

    netif_add(&g_netif, &gw, &mask, &ip, NULL, netif_init_cb, ip_input);
    netif_set_default(&g_netif);
    netif_set_up(&g_netif);

    // 5. Setup TCP Listener (Transparent Proxy)
    struct tcp_pcb* pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, g_config.lwip_listen_port);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, tcp_proxy_accept);

    LOG_INFO("[CORE] LwIP Stack Running. Proxy: %s:%d, WiFi Net: 192.168.137.0/24", g_config.proxy_ip.c_str(), g_config.proxy_port);

    SimpleHttpServer::instance().start(g_config.http_api_port);

    // 6. Main Loop
    uint32_t last_cleanup = get_now_ms();
    while (true) {
        MainDispatcher::instance().process_pending();

        {
            std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
            sys_check_timeouts();
        }
        
        if (get_now_ms() - last_cleanup > 5000) {
            last_cleanup = get_now_ms();
            udp_check_timeouts();
            NatTable::instance().cleanup(300000); 
            WiFiAPManager::instance().CheckKeepAlive();
        }

        Sleep(100); // Reduce CPU usage
    }
    return 0;
}
