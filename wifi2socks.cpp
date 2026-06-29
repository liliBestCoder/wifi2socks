#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <psapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Psapi.lib")

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
#include <cctype>
#include <vector>

#include "traffic_manager.h"
#include "http_server.h"
#include "wifi_ap.h"
#include "wifi_ap_listener.h"
#include "adapter.h"

DhcpServer* g_dhcp_server_ptr = nullptr;

enum class ApMode {
    WifiAp,
    WiredAp
};

static std::string get_env_string(const char* name) {
    DWORD len = GetEnvironmentVariableA(name, nullptr, 0);
    if (len == 0) return "";
    std::string value(len, '\0');
    GetEnvironmentVariableA(name, value.data(), len);
    if (!value.empty() && value.back() == '\0') value.pop_back();
    return value;
}

static std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static ApMode resolve_ap_mode() {
    std::string mode = get_env_string("WIFI2SOCKS_MODE");
    if (mode.empty()) mode = get_env_string("AP_MODE");
    if (mode.empty()) mode = g_config.ap_mode;
    mode = lower_copy(mode);
    if (mode == "wired" || mode == "wired_ap" || mode == "ethernet" || mode == "ethernet_ap") {
        return ApMode::WiredAp;
    }
    return ApMode::WifiAp;
}

static const char* mode_name(ApMode mode) {
    return mode == ApMode::WifiAp ? "wifi_ap" : "wired_ap";
}

static std::string narrow_lossy(const std::wstring& s) {
    std::string out;
    out.reserve(s.size());
    for (wchar_t ch : s) out.push_back(ch >= 0 && ch <= 127 ? (char)ch : '?');
    return out;
}

static void get_gateway_neighbor_counts(size_t& total, size_t& reachable) {
    total = 0;
    reachable = 0;

    IN_ADDR gateway_addr = {};
    if (inet_pton(AF_INET, g_config.gateway_ip.c_str(), &gateway_addr) != 1) {
        return;
    }
    uint32_t gateway_h = ntohl(gateway_addr.S_un.S_addr);
    uint32_t subnet_h = gateway_h & 0xFFFFFF00u;

    DWORD table_size = 0;
    DWORD err = GetIpNetTable(nullptr, &table_size, FALSE);
    if (err != ERROR_INSUFFICIENT_BUFFER || table_size == 0) {
        return;
    }

    std::vector<unsigned char> buffer(table_size);
    PMIB_IPNETTABLE table = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());
    if (GetIpNetTable(table, &table_size, FALSE) != NO_ERROR) {
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_IPNETROW& row = table->table[i];
        uint32_t ip_h = ntohl(row.dwAddr);
        if ((ip_h & 0xFFFFFF00u) != subnet_h) {
            continue;
        }
        total++;
        if (row.dwType == MIB_IPNET_TYPE_DYNAMIC || row.dwType == MIB_IPNET_TYPE_STATIC) {
            reachable++;
        }
    }
}

static void log_nethealth() {
    PROCESS_MEMORY_COUNTERS_EX pmc = {};
    pmc.cb = sizeof(pmc);
    unsigned long long working_mb = 0;
    unsigned long long private_mb = 0;
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        working_mb = (unsigned long long)(pmc.WorkingSetSize / (1024 * 1024));
        private_mb = (unsigned long long)(pmc.PrivateUsage / (1024 * 1024));
    }

    size_t neigh_total = 0;
    size_t neigh_reachable = 0;
    get_gateway_neighbor_counts(neigh_total, neigh_reachable);

    LOG_WARN("[NETHEALTH] mem_working_mb=%llu mem_private_mb=%llu gateway=%s neigh24_total=%zu neigh24_active=%zu",
        working_mb,
        private_mb,
        g_config.gateway_ip.c_str(),
        neigh_total,
        neigh_reachable);
}

static int reset_all_winpkfilter_adapter_modes() {
    CNdisApi api;
    if (!api.IsDriverLoaded()) {
        std::cout << "WinPkFilter driver is not loaded." << std::endl;
        return 1;
    }

    TCP_AdapterList adapters = {};
    if (!api.GetTcpipBoundAdaptersInfo(&adapters)) {
        std::cout << "GetTcpipBoundAdaptersInfo failed." << std::endl;
        return 1;
    }

    std::cout << "Resetting WinPkFilter adapter modes for " << adapters.m_nAdapterCount << " adapters." << std::endl;
    for (UINT i = 0; i < adapters.m_nAdapterCount; ++i) {
        ADAPTER_MODE mode = { adapters.m_nAdapterHandle[i], 0 };
        BOOL event_ok = api.SetPacketEvent(adapters.m_nAdapterHandle[i], nullptr);
        BOOL mode_ok = api.SetAdapterMode(&mode);
        std::cout << "  [" << (mode_ok ? "OK" : "FAIL") << "] "
                  << reinterpret_cast<char*>(adapters.m_szAdapterNameList[i])
                  << " mode=0 event=" << (event_ok ? "cleared" : "not-cleared")
                  << std::endl;
    }
    return 0;
}

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    if (GetEnvironmentVariableA("RESET_WINPK_ONLY", nullptr, 0) > 0) {
        int rc = reset_all_winpkfilter_adapter_modes();
        WSACleanup();
        return rc;
    }

    SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

    Microsoft::WRL::Wrappers::RoInitializeWrapper initialize(RO_INIT_MULTITHREADED);
    if (FAILED(initialize)) return 1;

    load_config("config.ini");
    ApMode ap_mode = resolve_ap_mode();
    g_config.ap_mode = mode_name(ap_mode);
    if (ap_mode == ApMode::WifiAp) {
        g_config.gateway_ip = WIFI_AP_GATEWAY_IP;
    } else {
        g_config.gateway_ip = g_config.wired_ap_gateway_ip;
    }

    // Configure Log Level
    std::string level_str = g_config.log_level;
    std::transform(level_str.begin(), level_str.end(), level_str.begin(), ::tolower);
    if (level_str == "debug") AsyncLogger::instance().set_level(LOG_LEVEL_DEBUG);
    else if (level_str == "warn") AsyncLogger::instance().set_level(LOG_LEVEL_WARN);
    else if (level_str == "error") AsyncLogger::instance().set_level(LOG_LEVEL_ERROR);
    else AsyncLogger::instance().set_level(LOG_LEVEL_INFO); // Default

    AsyncLogger::instance().init("wifi2socks.log");

    LOG_INFO("[CORE] Starting in %s mode. gateway_ip=%s", mode_name(ap_mode), g_config.gateway_ip.c_str());

    static Wifi2SocksWiFiListener wifi_listener;
    if (ap_mode == ApMode::WifiAp) {
        try {
            std::wstring ssid(g_config.wifi_ssid.begin(), g_config.wifi_ssid.end());
            std::wstring pass(g_config.wifi_password.begin(), g_config.wifi_password.end());
            WiFiAPManager::instance().SetSSID(ssid);
            WiFiAPManager::instance().SetPassphrase(pass);
            WiFiAPManager::instance().RegisterListener(&wifi_listener);
            WiFiAPManager::instance().Start();
            LOG_WARN("[CORE] wifi_ap mode: Wi-Fi Direct IP/DHCP is owned by ICS; built-in DHCP is disabled.");
            LOG_INFO("[CORE] WiFi AP Started.");
        } catch (...) {
            LOG_ERROR("[CORE] Failed to start WiFi AP.");
        }
    } else {
        LOG_WARN("[CORE] wired_ap mode: Wi-Fi Direct AP is not started; built-in DHCP will serve the configured wired subnet.");
    }

    bool skip_dhcp = ap_mode == ApMode::WifiAp;
    static DhcpServer dhcp_server(g_config.gateway_ip);
    if (skip_dhcp) {
        LOG_WARN("[CORE] Built-in DHCP server is disabled in wifi_ap mode.");
    } else {
        g_dhcp_server_ptr = &dhcp_server;
        dhcp_server.start();
    }

    TrafficManager::instance().start();

    GeoChecker::instance().init();
    LOG_INFO("[CORE] GeoChecker Initialized.");

    PacketPool::instance().init(32768);

    std::string adapter_name;
    if (ap_mode == ApMode::WifiAp) {
        adapter_name = find_best_wifi_direct_adapter();
    } else {
        auto wired_adapters = get_ethernet_adapters(g_config.wired_adapter_hint);
        if (!wired_adapters.empty()) {
            const auto& wired = wired_adapters[0];
            adapter_name = wired.guid_name;
            if (std::string(WIFI_AP_GATEWAY_IP) != g_config.gateway_ip) {
                remove_adapter_ipv4(wired.luid, WIFI_AP_GATEWAY_IP);
            }
            if (ensure_adapter_ipv4(wired.luid, g_config.gateway_ip, 24)) {
                LOG_INFO("[CORE] wired_ap adapter configured: %s (%s), IP %s/24",
                    adapter_name.c_str(), narrow_lossy(wired.description).c_str(), g_config.gateway_ip.c_str());
            } else {
                LOG_ERROR("[CORE] Failed to configure wired_ap adapter IP %s/24.", g_config.gateway_ip.c_str());
            }
        }
    }
    
    int worker_count = std::thread::hardware_concurrency();
    if (worker_count == 0) worker_count = 4;
    WorkerPool::instance().init(8);
    LOG_INFO("[CORE] Worker pool initialized with %d workers sharing one IOCP.", worker_count);

    UdpProxy::initialize();

    if (!adapter_name.empty()) {
        LOG_INFO("[CORE] Adapter found: %s", adapter_name.c_str());
        if (!WinPkFilterDriver::instance().start_batch(adapter_name, [](std::vector<WinPkFilterDriver::Packet>&&) {}, ap_mode == ApMode::WifiAp)) {
            LOG_ERROR("[CORE] Failed to start WinPkFilter driver with internal NAT.");
        } else {
            LOG_INFO("[CORE] WinPkFilter driver started with internal NAT.");
        }
    } else {
        LOG_ERROR("[CORE] No adapter found for mode %s.", mode_name(ap_mode));
    }

    AppListener::instance().start("0.0.0.0", 3080);
    SimpleHttpServer::instance().start(g_config.http_api_port);

    uint64_t last_keepalive = 0;
    uint64_t last_stats = 0;
    uint64_t last_nethealth = 0;
    uint64_t last_p2p_keepalive = 0;
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
            if (ap_mode == ApMode::WifiAp) {
                WiFiAPManager::instance().CheckKeepAlive();
            }
            ProxyTCP::check_all_timeouts();
            NatManager::instance().cleanup();
            last_keepalive = now;
        }

        if (now - last_nethealth > 5000) {
            log_nethealth();
            ProxyTCP::log_global_stats();
            UdpProxy::log_global_stats();
            last_nethealth = now;
        }

        // P2P keep-alive: send periodic packet to prevent 2-min disconnect
        if (now - last_p2p_keepalive > 30000 && ap_mode == ApMode::WifiAp && g_dhcp_server_ptr) {
            auto clients = g_dhcp_server_ptr->get_active_clients();
            SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
            if (s != INVALID_SOCKET) {
                for (uint32_t ip_h : clients) {
                    sockaddr_in addr;
                    addr.sin_family = AF_INET;
                    addr.sin_addr.s_addr = htonl(ip_h);
                    addr.sin_port = htons(9);
                    sendto(s, "", 1, 0, (sockaddr*)&addr, sizeof(addr));
                }
                closesocket(s);
            }
            last_p2p_keepalive = now;
        }

        WaitForSingleObject(MainDispatcher::instance().get_event_handle(), 100);
    }
    return 0;
}
