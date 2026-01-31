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

