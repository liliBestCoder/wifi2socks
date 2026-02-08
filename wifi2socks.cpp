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

// Global Instances for Hijacking
DhcpServer* g_dhcp_server_ptr = nullptr;

// Main Entry Point
int main() {
    // ... (previous initialization code) ...
    load_config("config.ini");

    // 0. Initialize WiFi AP
    // ... (rest of WiFi initialization) ...

    // Start DHCP Server
    static DhcpServer dhcp_server(g_config.tap_ip);
    g_dhcp_server_ptr = &dhcp_server;
    dhcp_server.start();

    // ... ( GeoChecker and other init ) ...

    // 1. Initialize WinDivert
    // ULTIMATE HIJACK FILTER: 
    // 1. Intercept ALL DHCP (67,68)
    // 2. Intercept our subnet (11.x)
    // 3. Intercept Windows default subnet (137.x) to rescue "stuck" clients
    std::string base_ip = g_config.tap_ip;
    size_t last_dot = base_ip.find_last_of('.');
    std::string subnet = base_ip.substr(0, last_dot);
    
    std::string filter = "(udp.DstPort == 67 or udp.SrcPort == 67 or udp.DstPort == 68 or udp.SrcPort == 68) or "
                         "(ip and ((ip.SrcAddr >= " + subnet + ".0 and ip.SrcAddr <= " + subnet + ".255) or "
                         "(ip.SrcAddr >= 192.168.137.0 and ip.SrcAddr <= 192.168.137.255)) "
                         "and not tcp.SrcPort == 8080)";
    
    static WinDivertDriver divert(filter);
    set_windivert_driver(&divert);
    WinDivertDriver::PacketHandler handler = [](const char* packet, size_t length, const WINDIVERT_ADDRESS* addr) {
        std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
        TrafficManager::instance().report_tap_tx(length); // Use same traffic counter
        process_ip_packet(packet, (int)length, addr);
    };

    // 2. Initialize Worker Pool
    WorkerPool::instance().init(8);
    LOG_INFO("[CORE] Worker Pool Initialized.");

    // 4. Initialize LwIP
    lwip_init();

    ip4_addr_t ip, mask, gw;
    ip4addr_aton(g_config.tap_ip.c_str(), &ip);
    ip4addr_aton("255.255.0.0", &mask); // Use 255.255.0.0 to cover hijack subnets (11.x & 137.x)
    ip4addr_aton("0.0.0.0", &gw); 

    netif_add(&g_netif, &gw, &mask, &ip, NULL, netif_init_cb, ip_input);
    netif_set_default(&g_netif);
    netif_set_up(&g_netif);

    // Start WinDivert capture AFTER LwIP is ready
    divert.start(handler);

    // 5. Setup TCP Listener (Transparent Proxy)
    struct tcp_pcb* pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, g_config.lwip_listen_port);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, tcp_proxy_accept);

    LOG_INFO("[CORE] LwIP Stack Running. Proxy: %s:%d, WiFi Gateway: %s", g_config.proxy_ip.c_str(), g_config.proxy_port, g_config.tap_ip.c_str());

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
