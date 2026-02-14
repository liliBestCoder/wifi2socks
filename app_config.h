#pragma once

#include <string>
#include <vector>
#include <cstdint>

// --- Configuration Struct ---
struct AppConfig {
    std::string tap_ip;
    std::string tap_netmask;
    std::string tap_gateway;
    std::string tap_mac; // e.g. "00:FF:..."
    
    std::string proxy_ip;
    uint16_t proxy_port;
    std::string proxy_dns_server;
    std::string direct_dns_server;
    
    uint16_t lwip_listen_port;
    uint32_t max_sni_len;
    uint16_t http_api_port;

    // WiFi settings
    std::string wifi_ssid;
    std::string wifi_password;

    // Rules (Persisted)
    std::vector<std::string> direct_ip_list;
    std::vector<std::string> direct_domain_list;
    std::vector<std::string> block_ip_list;
    std::vector<std::string> block_domain_list;
    std::vector<std::string> proxy_ip_list;
    std::vector<std::string> proxy_domain_list;

    // Defaults
    AppConfig() {
        tap_ip = "10.0.0.1";
        tap_netmask = "255.255.255.0";
        tap_gateway = "10.0.0.1";
        tap_mac = "00:FF:92:EA:69:5C";
        
        proxy_ip = "127.0.0.1";
        proxy_port = 2080;
        proxy_dns_server = "8.8.8.8";
        direct_dns_server = "223.5.5.5";
        
        lwip_listen_port = 7000;
        max_sni_len = 4096;
        http_api_port = 8080;

        wifi_ssid = "wifi2socks_ap";
        wifi_password = "password123";
    }
};

extern AppConfig g_config;

// Keep some defines for backward compatibility if needed, or point them to g_config
// But best to replace usages.

#define TAP_WIN_PATH "\\\\.\\%s.tap"
#define TAP_CONTROL_CODE(request, method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)

#include <stdio.h>
#include "logger.h"

enum LogLevel {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_ERROR = 2,
    LOG_LEVEL_NONE = 99
};

extern LogLevel g_log_level;


#define LOG_PRINT(level, fmt, ...) do { \
    if (level >= g_log_level) { \
        AsyncLogger::instance().log(fmt, ##__VA_ARGS__); \
    } \
} while(0)

#define LOG_DEBUG(fmt, ...) LOG_PRINT(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  LOG_PRINT(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)  LOG_PRINT(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
