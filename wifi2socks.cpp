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
#include "packet_monitor.h"
#include "dhcp_server.h"
#include "worker.h"
#include "proxy_tcp.h"
#include "proxy_udp.h"
#include "main_dispatcher.h"
#include "geo_checker.h"
#include "config_loader.h"
#include "app_listener.h"
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
                        return "\\\\Device\\\\\\" + name;
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
    } catch (...) {
        LOG_ERROR("[CORE] Failed to start WiFi AP.");
    }
    
    static DhcpServer dhcp_server(g_config.tap_ip);
    g_dhcp_server_ptr = &dhcp_server;
    dhcp_server.start();

    TrafficManager::instance().start();

    GeoChecker::instance().init();
    LOG_INFO("[CORE] GeoChecker Initialized.");

    // IMPORTANT: PacketPool must be initialized before the driver starts
    PacketPool::instance().init(8192);
    PacketMonitor::instance().start();

    std::string adapter_name = find_adapter_by_ip(g_config.tap_ip);
    static WinPkFilterDriver pk_driver;
    
    int worker_count = std::thread::hardware_concurrency();
    if (worker_count == 0) worker_count = 4;
    WorkerPool::instance().init(worker_count);
    LOG_INFO("[CORE] Worker pool initialized with %d workers.", worker_count);

    UdpProxy::initialize();

    // LwIP stack and netif initialization has been removed.
    // The new NAT logic is self-contained within the WinPkFilterDriver.
    
    if (!adapter_name.empty()) {
        // The driver's get_adapter_mac is no longer needed here as the driver handles its own setup.
        LOG_INFO("[CORE] Adapter found: %s", adapter_name.c_str());
    }
    
    // The driver now handles packet processing internally for NAT.
    // We no longer need to pass a complex packet handler.
    if (!adapter_name.empty()) {
        if (!pk_driver.start_batch(adapter_name, [](std::vector<WinPkFilterDriver::Packet>&&) {})) {
            LOG_ERROR("[CORE] Failed to start WinPkFilter driver with internal NAT.");
        } else {
            LOG_INFO("[CORE] WinPkFilter driver started with internal NAT.");
        }
    }

    // Start the new application listener on 0.0.0.0:3080.
    // This will handle incoming TCP connections and UDP packets redirected by the driver.
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
        
        // LwIP timeout checks are no longer needed.
        // The old NatTable cleanup is also removed; NatManager has its own.

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
            last_keepalive = now;
        }

        WaitForSingleObject(MainDispatcher::instance().get_event_handle(), 100); // Wait with a timeout
    }
    return 0;
}
