#pragma once

// --- Configuration ---
#define TAP_IP          "10.0.0.1"
#define TAP_NETMASK     "255.255.255.0"
#define TAP_GW          "10.0.0.1" 
#define PROXY_IP        "127.0.0.1"
#define PROXY_PORT      2080
#define LWIP_LISTEN_PORT 7000
#define MAX_SNI_LEN     4096

#define TAP_CONTROL_CODE(request, method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)

#define TAP_WIN_PATH "\\\\.\\%s.tap"

#include <stdio.h>
#include "logger.h"

enum LogLevel {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
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

