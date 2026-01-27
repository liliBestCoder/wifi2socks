#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <vector>
#include <string>
#include <thread>
#include <cstdio>
#include <windows.h>
#include <winioctl.h>
#include "packet.h"
#include "queue.h"
#include "worker.h"
#include "arp.h"


#pragma comment(lib, "Ws2_32.lib")

#define TAP_CONTROL_CODE(request, method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)

#define TAP_WIN_PATH "\\\\.\\Global\\%s.tap"

int main()
{
    char devicePath[256];
    sprintf_s(devicePath, sizeof(devicePath),
        TAP_WIN_PATH,
        "{92EA695C-EDAD-44C4-9950-3F306CBE9A7D}");

    printf("Opening TAP device: %s\n", devicePath);

    HANDLE tap = CreateFileA(
        devicePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        0,
        OPEN_EXISTING,
        0,     // <----- 关键：不要 OVERLAPPED
        0
    );

    if (tap == INVALID_HANDLE_VALUE) {
        printf("Error opening TAP device. Code=%lu\n", GetLastError());
        return 1;
    }

    printf("TAP opened successfully.\n");

    DWORD len;
    ULONG status = TRUE;

    if (!DeviceIoControl(tap,
        TAP_IOCTL_SET_MEDIA_STATUS,
        &status, sizeof(status),
        &status, sizeof(status),
        &len,
        NULL))
    {
        printf("Failed to set TAP media status. Code=%lu\n", GetLastError());
        CloseHandle(tap);
        return 1;
    }

    printf("TAP media status set to connected.\n");

    // init winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    init_workers(tap);

    uint8_t buffer[65536];

    while (true) {
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(tap, buffer, sizeof(buffer), &bytesRead, NULL);
        if (!ok) {
            printf("ReadFile failed: %lu\n", GetLastError());
            break;
        }
        if (bytesRead < sizeof(EthHeader)) continue;
		dispatch(buffer, bytesRead);
    }
    CloseHandle(tap);
    WSACleanup();
    return 0;
}
