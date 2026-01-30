#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <cstdint>
#include <mutex>

class TapDriver {
public:
    static TapDriver& instance();
    
    bool init(const char* device_guid);
    void send_async(const uint8_t* buf, int len);
    HANDLE handle() const { return m_tap; }
    
    // Config
    static const uint8_t TAP_MAC[6];
    
private:
    HANDLE m_tap;
    std::mutex m_write_mtx;
};
