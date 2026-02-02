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
#include "tap_driver.h"
#include "worker.h"
#include "lwip_handler.h"
#include "proxy_tcp.h"
#include "proxy_udp.h"
#include "main_dispatcher.h"
#include "nat_table.h"
#include "geo_checker.h"
#include <iostream>
#include <thread>

// Main Entry Point
int main() {
    // 0. Pre-load GeoIP/GeoSite
    try {
        GeoChecker::instance();
        LOG_INFO("GeoChecker loaded successfully.\n");
    } catch (const std::exception& e) {
        LOG_INFO("Warning: GeoChecker failed to load: %s. IP/Domain bypass may not work.\n", e.what());
    }

    // 1. Initialize TAP Device
    const char* tap_guid = "{92EA695C-EDAD-44C4-9950-3F306CBE9A7D}";
    printf("Opening TAP device...\n");
    if (!TapDriver::instance().init(tap_guid)) {
        printf("Error opening TAP device. Check GUID and Driver.\n");
        return 1;
    }

    // 2. Initialize Winsock
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // 3. Initialize Worker Pool
    WorkerPool::instance().init(80);
    LOG_INFO("Worker Pool Initialized.\n");

    // 4. Initialize LwIP
    lwip_init();

    ip4_addr_t ip, mask, gw;
    ip4addr_aton(TAP_IP, &ip);
    ip4addr_aton(TAP_NETMASK, &mask);
    ip4addr_aton(TAP_GW, &gw);

    netif_add(&g_netif, &ip, &mask, &gw, NULL, netif_init_cb, ethernet_input);
    netif_set_default(&g_netif);
    netif_set_up(&g_netif);

    // 5. Setup TCP Listener (Transparent Proxy)
    struct tcp_pcb* pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, LWIP_LISTEN_PORT);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, tcp_proxy_accept);

    LOG_INFO("LwIP Tun2Socks Running.\nProxy: %s:%d\nTAP IP: %s\n", PROXY_IP, PROXY_PORT, TAP_IP);

    // 6. Main Loop (Read from TAP -> LwIP)
    uint8_t buffer[65536];
    OVERLAPPED ol = {0};
    ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    DWORD bytesRead = 0;
    bool pending = false;
    uint32_t last_cleanup = get_now_ms();

    HANDLE tapHandle = TapDriver::instance().handle();

    while (true) {
        // --- PROCESS PENDING TASKS FROM WORKERS ---
        // This handles the "Downstream" writes to LwIP without locking in Workers
        MainDispatcher::instance().process_pending();
        // ------------------------------------------

        if (!pending) {
            if (!ReadFile(tapHandle, buffer, sizeof(buffer), &bytesRead, &ol)) {
                if (GetLastError() != ERROR_IO_PENDING) {
                    printf("TAP Read Error: %lu\n", GetLastError());
                    break;
                }
                pending = true;
            } else {
                {
                    std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
                    process_tap_frame(buffer, bytesRead);
                }
                pending = false; 
                ol.Offset = 0; ol.OffsetHigh = 0; 
            }
        }

        if (pending) {
            DWORD waitRes = WaitForSingleObject(ol.hEvent, 2); 
            if (waitRes == WAIT_OBJECT_0) {
                if (GetOverlappedResult(tapHandle, &ol, &bytesRead, FALSE)) {
                    std::lock_guard<std::recursive_mutex> lock(g_lwip_mtx);
                    process_tap_frame(buffer, bytesRead);
                }
                pending = false;
                ResetEvent(ol.hEvent);
                ol.Offset = 0; ol.OffsetHigh = 0;
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