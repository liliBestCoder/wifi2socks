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

// Removed redundant g_log_level, now managed by AsyncLogger

#include "winpkfilter_driver.h"
#include "packet_pool.h"

#include "dhcp_server.h"
#include "worker.h"
#include "proxy_tcp.h"
#include "proxy_udp.h"
#include "main_dispatcher.h"
#include "geo_checker.h"
#include "config_loader.h"
#include "app_listener.h"
#include "logger.h" // Added include for Logger configuration
#include <iostream>
#include <thread>
#include <shellapi.h>
#include <algorithm> // For std::transform

#include "traffic_manager.h"
#include "http_server.h"
#include "wifi_ap.h"
#include "wifi_ap_listener.h"
#include "adapter.h"

DhcpServer* g_dhcp_server_ptr = nullptr;

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

    Microsoft::WRL::Wrappers::RoInitializeWrapper initialize(RO_INIT_MULTITHREADED);
    if (FAILED(initialize)) return 1;

    load_config("config.ini");

    // Configure Log Level
    std::string level_str = g_config.log_level;
    std::transform(level_str.begin(), level_str.end(), level_str.begin(), ::tolower);
    if (level_str == "debug") AsyncLogger::instance().set_level(LOG_LEVEL_DEBUG);
    else if (level_str == "warn") AsyncLogger::instance().set_level(LOG_LEVEL_WARN);
    else if (level_str == "error") AsyncLogger::instance().set_level(LOG_LEVEL_ERROR);
    else AsyncLogger::instance().set_level(LOG_LEVEL_INFO); // Default

    AsyncLogger::instance().init("wifi2socks.log");

    static Wifi2SocksWiFiListener wifi_listener;
    try {
        std::wstring ssid(g_config.wifi_ssid.begin(), g_config.wifi_ssid.end());
        std::wstring pass(g_config.wifi_password.begin(), g_config.wifi_password.end());
        WiFiAPManager::instance().SetSSID(ssid);
        WiFiAPManager::instance().SetPassphrase(pass);
        WiFiAPManager::instance().RegisterListener(&wifi_listener);
        WiFiAPManager::instance().Start();
		WiFiAPManager::instance().SetIP(g_config.gateway_ip);
        LOG_INFO("[CORE] WiFi AP Started.");
    } catch (...) {
        LOG_ERROR("[CORE] Failed to start WiFi AP.");
    }

    static DhcpServer dhcp_server(g_config.gateway_ip);
    g_dhcp_server_ptr = &dhcp_server;
    dhcp_server.start();

    TrafficManager::instance().start();

    GeoChecker::instance().init();
    LOG_INFO("[CORE] GeoChecker Initialized.");

    PacketPool::instance().init(1024 * 64);

    std::string adapter_name = find_best_wifi_direct_adapter();
    static WinPkFilterDriver pk_driver;
    
    int worker_count = std::thread::hardware_concurrency();
    if (worker_count == 0) worker_count = 4;
    WorkerPool::instance().init(8);
    LOG_INFO("[CORE] Worker pool initialized with %d workers sharing one IOCP.", worker_count);

    UdpProxy::initialize();

    if (!adapter_name.empty()) {
        LOG_INFO("[CORE] Adapter found: %s", adapter_name.c_str());
        if (!pk_driver.start_batch(adapter_name, [](std::vector<WinPkFilterDriver::Packet>&&) {})) {
            LOG_ERROR("[CORE] Failed to start WinPkFilter driver with internal NAT.");
        } else {
            LOG_INFO("[CORE] WinPkFilter driver started with internal NAT.");
        }
    }

    AppListener::instance().start("0.0.0.0", 3080);
    SimpleHttpServer::instance().start(g_config.http_api_port);

    uint64_t last_keepalive = 0;
    uint64_t last_stats = 0;
    size_t peak_q_size = 0;

    while (true) {
        size_t current_q_size = MainDispatcher::instance().get_queue_size();
        if (current_q_size > peak_q_size) {
            peak_q_size = current_q_size;
        }

        MainDispatcher::instance().process_pending();
        
        uint64_t now = GetTickCount64();

        if (now - last_stats > 1000) {
            if (peak_q_size > 0) {
                LOG_INFO("[CORE] Main thread queue peak size (last 1s): %llu", (unsigned long long)peak_q_size);
                peak_q_size = 0; 
            }
            last_stats = now;
        }

        if (now - last_keepalive > 1000) {
            WiFiAPManager::instance().CheckKeepAlive();
            ProxyTCP::check_all_timeouts();
            NatManager::instance().cleanup_expired();
            last_keepalive = now;
        }

        WaitForSingleObject(MainDispatcher::instance().get_event_handle(), 100);
    }
    return 0;
}
