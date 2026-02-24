#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "logger.h" // Include logger.h for LogLevel and AsyncLogger

// --- Configuration Struct ---
struct AppConfig {
    std::string gateway_ip; // Previously tap_ip
    
    std::string upstream_ip;   // Previously proxy_ip
    uint16_t upstream_port;    // Previously proxy_port
    
    std::string proxy_dns_server;
    std::string direct_dns_server;
    
    uint16_t http_api_port;
    std::string log_level; // New field

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
        gateway_ip = "192.168.11.1"; // Updated default to match user preference
        
        upstream_ip = "127.0.0.1";
        upstream_port = 2080;
        
        proxy_dns_server = "8.8.8.8";
        direct_dns_server = "223.5.5.5";
        
        http_api_port = 8080;
        log_level = "info"; // Default log level

        wifi_ssid = "wifi2socks_ap";
        wifi_password = "password123";
    }
};

extern AppConfig g_config;

// Keep some defines for backward compatibility if needed, or point them to g_config
#define TAP_WIN_PATH "\\\\.\\%s.tap"
#define TAP_CONTROL_CODE(request, method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)

#include <stdio.h>

// Macros update: Pass level to AsyncLogger::log
#define LOG_DEBUG(fmt, ...) AsyncLogger::instance().log(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  AsyncLogger::instance().log(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  AsyncLogger::instance().log(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) AsyncLogger::instance().log(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
