#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <cstdint>
#include <vector>
#include <atomic>
#include "wintun.h"

class TunDriver {
public:
    static TunDriver& instance();
    
    bool init(const char* device_guid);
    
    // Sends an Ethernet frame (strips header, sends IP packet to Wintun)
    void send_async(const uint8_t* buf, int len);
    
    // Wintun Read Event (Use with WaitForSingleObject)
    HANDLE get_read_wait_event();
    
    // Reads a packet into the provided buffer.
    // Returns number of bytes written to 'buf'.
    // Prepends Fake Ethernet Header to the IP packet from Wintun.
    uint32_t read(uint8_t* buf, uint32_t max_len);

    static uint8_t TAP_MAC[6]; 

private:
    TunDriver();
    ~TunDriver();
    
    bool load_wintun_library();

    HMODULE m_wintun_dll;
    WINTUN_ADAPTER_HANDLE m_adapter;
    WINTUN_SESSION_HANDLE m_session;
    
    // API Pointers
    WINTUN_CREATE_ADAPTER_FUNC pWintunCreateAdapter;
    WINTUN_CLOSE_ADAPTER_FUNC pWintunCloseAdapter;
    WINTUN_START_SESSION_FUNC pWintunStartSession;
    WINTUN_END_SESSION_FUNC pWintunEndSession;
    WINTUN_GET_READ_WAIT_EVENT_FUNC pWintunGetReadWaitEvent;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC pWintunAllocateSendPacket;
    WINTUN_SEND_PACKET_FUNC pWintunSendPacket;
    WINTUN_RECEIVE_PACKET_FUNC pWintunReceivePacket;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC pWintunReleaseReceivePacket;
};