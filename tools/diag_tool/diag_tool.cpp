#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wlanapi.h>
#include <iostream>
#include <thread>
#include <winevt.h>
#include <winsvc.h>
#include <ctime>
#include <vector>
#include <string>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")

// WinPkFilter Constants & Structures
#define IOCTL_NDISRD_GET_ADAPTER_LIST      0x00122007
#define IOCTL_NDISRD_ADAPTER_MODE          0x0012200B
#define MSTCP_FLAG_SENT_TUNNEL             0x00000001
#define MSTCP_FLAG_RECV_TUNNEL             0x00000002

typedef struct _TCP_AdapterList {
    ULONG m_nAdapterCount;
    unsigned char m_szAdapterName[256][256];
    HANDLE m_nAdapterHandle[256];
    unsigned char m_szAdapterMedium[256];
    ULONG m_nAdapterMediumSize[256];
} TCP_AdapterList;

typedef struct _ADAPTER_MODE {
    HANDLE m_hAdapter;
    ULONG dwFlags;
} ADAPTER_MODE;

std::string GetTime() {
    char b[32]; time_t n = time(0); struct tm t;
    localtime_s(&t, &n); strftime(b, 32, "%H:%M:%S", &t);
    return std::string(b);
}

void ProbeWinPkFilterDriver() {
    HANDLE hDevice = CreateFile(L"\\\\.\\ndisrd", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "[" << GetTime() << "] [CRITICAL] Cannot open WinPkFilter Device! Error: " << GetLastError() << std::endl;
        return;
    }

    while (true) {
        TCP_AdapterList adList;
        DWORD bytesReturned;
        if (DeviceIoControl(hDevice, IOCTL_NDISRD_GET_ADAPTER_LIST, NULL, 0, &adList, sizeof(adList), &bytesReturned, NULL)) {
            for (ULONG i = 0; i < adList.m_nAdapterCount; ++i) {
                std::string name = (char*)adList.m_szAdapterName[i];
                if (name.find("VNET_WIFI_DIRECT") != std::string::npos || name.find("Microsoft Wi-Fi Direct Virtual") != std::string::npos) {
                    ADAPTER_MODE mode = { adList.m_nAdapterHandle[i], 0 };
                    DWORD bytesRet2;
                    if (DeviceIoControl(hDevice, IOCTL_NDISRD_ADAPTER_MODE, &mode, sizeof(mode), &mode, sizeof(mode), &bytesRet2, NULL)) {
                        bool isTunnel = (mode.dwFlags & MSTCP_FLAG_SENT_TUNNEL) && (mode.dwFlags & MSTCP_FLAG_RECV_TUNNEL);
                        if (!isTunnel) {
                            std::cout << "[" << GetTime() << "] [CRITICAL] WiFi Direct Adapter NOT IN TUNNEL MODE! (Flags: " << mode.dwFlags << ")" << std::endl;
                        }
                    }
                }
            }
        } else {
            std::cout << "[" << GetTime() << "] [CRITICAL] WinPkFilter Driver STOPPED RESPONDING! Error Code: " << GetLastError() << std::endl;
        }
        Sleep(3000);
    }
}

int ResetWinPkFilterAdapters() {
    HANDLE hDevice = CreateFile(L"\\\\.\\ndisrd", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "[" << GetTime() << "] Cannot open WinPkFilter device. Error: " << GetLastError() << std::endl;
        return 1;
    }

    TCP_AdapterList adList = {};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDevice, IOCTL_NDISRD_GET_ADAPTER_LIST, NULL, 0, &adList, sizeof(adList), &bytesReturned, NULL)) {
        std::cout << "[" << GetTime() << "] Failed to get adapter list. Error: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    std::cout << "[" << GetTime() << "] Resetting WinPkFilter modes for " << adList.m_nAdapterCount << " adapters." << std::endl;
    for (ULONG i = 0; i < adList.m_nAdapterCount; ++i) {
        ADAPTER_MODE mode = { adList.m_nAdapterHandle[i], 0 };
        DWORD bytesRet2 = 0;
        std::string name = reinterpret_cast<char*>(adList.m_szAdapterName[i]);
        BOOL ok = DeviceIoControl(hDevice, IOCTL_NDISRD_ADAPTER_MODE, &mode, sizeof(mode), &mode, sizeof(mode), &bytesRet2, NULL);
        std::cout << "  [" << (ok ? "OK" : "FAIL") << "] " << name << " -> mode 0";
        if (!ok) std::cout << " error=" << GetLastError();
        std::cout << std::endl;
    }

    CloseHandle(hDevice);
    return 0;
}

void ProbeAppAlive() {
    while (true) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr; addr.sin_family = AF_INET; addr.sin_port = htons(3080);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        u_long mode = 1; ioctlsocket(s, FIONBIO, &mode);
        connect(s, (sockaddr*)&addr, sizeof(addr));
        fd_set writeSet; FD_ZERO(&writeSet); FD_SET(s, &writeSet);
        timeval tv = { 1, 0 };
        if (select(0, NULL, &writeSet, NULL, &tv) <= 0) { /* Silent */ }
        closesocket(s);
        Sleep(5000);
    }
}

int main(int argc, char** argv) {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    if (argc > 1 && std::string(argv[1]) == "--reset-winpk") {
        int rc = ResetWinPkFilterAdapters();
        WSACleanup();
        return rc;
    }
    std::cout << "====================================================" << std::endl;
    std::cout << "    wifi2socks Diagnostic Tool V6 (Error Code Trace)" << std::endl;
    std::cout << "====================================================" << std::endl;
    std::thread t1(ProbeWinPkFilterDriver);
    std::thread t2(ProbeAppAlive);
    t1.join(); t2.join();
    return 0;
}
