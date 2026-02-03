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

#include "tun_driver.h"
#include "worker.h"
#include "lwip/etharp.h"
#include "lwip_handler.h"
#include "proxy_tcp.h"
#include "proxy_udp.h"
#include "main_dispatcher.h"
#include "nat_table.h"
#include "geo_checker.h"
#include "config_loader.h"
#include <iostream>
#include <thread>

#include "traffic_manager.h"
#include "http_server.h"
#include "wifi_ap.h"
#include "wifi_ap_listener.h"

std::atomic<bool> g_tap_running(true);

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

    // 0. Initialize WiFi AP (Don't start yet, let HTTP API control it)
    static Wifi2SocksWiFiListener wifi_listener; // Static to keep it alive
    try {
        std::wstring ssid(g_config.wifi_ssid.begin(), g_config.wifi_ssid.end());
        std::wstring pass(g_config.wifi_password.begin(), g_config.wifi_password.end());

        WiFiAPManager::instance().SetSSID(ssid);
        WiFiAPManager::instance().SetPassphrase(pass);
        WiFiAPManager::instance().RegisterListener(&wifi_listener);
        LOG_INFO("WiFi AP Initialized (SSID: %s). Wait for START command.\n", g_config.wifi_ssid.c_str());
    } catch (const std::exception& e) {
        LOG_INFO("WiFi AP Initialization failed: %s\n", e.what());
    }
    
    // -0.5 Start Traffic Manager & HTTP API
    TrafficManager::instance().start();
    SimpleHttpServer::instance().start(g_config.http_api_port);

    // 0.5 Pre-load GeoIP/GeoSite
    try {
        GeoChecker::instance().init();
        LOG_INFO("GeoChecker loading in background...\n");
    } catch (const std::exception& e) {
        LOG_INFO("Warning: GeoChecker failed to load: %s. IP/Domain bypass may not work.\n", e.what());
    }

    // 1. Initialize TUN Device (Wintun)
    const char* tap_guid = "{92EA695C-EDAD-44C4-9950-3F306CBE9A7D}";
    printf("Opening TUN device...\n");
    if (!TunDriver::instance().init(tap_guid)) {
        printf("Error opening TUN device. Check GUID and Driver.\n");
        return 1;
    }

    // 2. Initialize Worker Pool
    WorkerPool::instance().init(20);
    LOG_INFO("Worker Pool Initialized.\n");

    // 4. Initialize LwIP
    lwip_init();

    ip4_addr_t ip, mask, gw;
    ip4addr_aton(g_config.tap_ip.c_str(), &ip);
    ip4addr_aton(g_config.tap_netmask.c_str(), &mask);
    ip4addr_aton(g_config.tap_gateway.c_str(), &gw);

    netif_add(&g_netif, &ip, &mask, &gw, NULL, netif_init_cb, ethernet_input);
    netif_set_default(&g_netif);
    netif_set_up(&g_netif);

    // 4.1 Static ARP for Gateway (Required for Wintun/L3)
    // Since Wintun is L3, it won't answer ARP. We must tell LwIP the Gateway's MAC is our fake one.
    struct eth_addr gw_eth;
    gw_eth.addr[0]=0x00; gw_eth.addr[1]=0x00; gw_eth.addr[2]=0x00; gw_eth.addr[3]=0x00; gw_eth.addr[4]=0x00; gw_eth.addr[5]=0x01;
    etharp_add_static_entry(&gw, &gw_eth);

    // 5. Setup TCP Listener (Transparent Proxy)
    struct tcp_pcb* pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, g_config.lwip_listen_port);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, tcp_proxy_accept);

    LOG_INFO("LwIP Tun2Socks Running.\nProxy: %s:%d\nTAP IP: %s\n", g_config.proxy_ip.c_str(), g_config.proxy_port, g_config.tap_ip.c_str());

    // 6. Main Loop (Read from TUN -> LwIP)
    uint8_t buffer[65536];
    uint32_t last_cleanup = get_now_ms();

    HANDLE waitEvent = TunDriver::instance().get_read_wait_event();

    while (true) {
        // This handles the "Downstream" writes to LwIP without locking in Workers
        MainDispatcher::instance().process_pending();
        
        if (!g_tap_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue; 
        }

        // Wait for packet (or timeout to process pending/timeouts)
        DWORD waitRes = WaitForSingleObject(waitEvent, 2); 
        
        if (waitRes == WAIT_OBJECT_0) {
             // Read all available packets (Wintun is fast)
             uint32_t len = 0;
             while ((len = TunDriver::instance().read(buffer, sizeof(buffer))) > 0) {
                 std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
                 TrafficManager::instance().report_tap_tx(len);
                 process_tap_frame(buffer, len);
             }
        }

        {
            std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
            sys_check_timeouts();
        }
        
        // Clean UDP sessions
        if (get_now_ms() - last_cleanup > 5000) {
            last_cleanup = get_now_ms();
            udp_check_timeouts();
            NatTable::instance().cleanup(60000); // 1 Minute timeout for NAT entries
        }
    }
    return 0;
}
