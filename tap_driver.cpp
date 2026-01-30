#include "tap_driver.h"
#include "app_config.h"
#include <cstdio>
#include <winioctl.h>

const uint8_t TapDriver::TAP_MAC[6] = { 0x00, 0xFF, 0x92, 0xEA, 0x69, 0x5C };

TapDriver& TapDriver::instance() {
    static TapDriver inst;
    return inst;
}

bool TapDriver::init(const char* device_guid) {
    char devicePath[256];
    sprintf_s(devicePath, sizeof(devicePath), TAP_WIN_PATH, device_guid);
    
    m_tap = CreateFileA(devicePath, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    
    if (m_tap == INVALID_HANDLE_VALUE) return false;

    ULONG status = TRUE; DWORD len;
    DeviceIoControl(m_tap, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL);
    return true;
}

void TapDriver::send_async(const uint8_t* buf, int len) {
    if (len <= 0 || m_tap == INVALID_HANDLE_VALUE) return;
    std::lock_guard<std::mutex> lk(m_write_mtx);
    OVERLAPPED ol = {0};
    ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ol.hEvent) return;
    DWORD written = 0;
    if (!WriteFile(m_tap, buf, len, &written, &ol)) {
        if (GetLastError() == ERROR_IO_PENDING) {
            WaitForSingleObject(ol.hEvent, 1000); 
        }
    }
    CloseHandle(ol.hEvent);
}
