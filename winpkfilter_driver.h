#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tchar.h>
#include <string>
#include <functional>
#include <thread>
#include <vector>
#include <mutex>

// WinPkFilter SDK headers
#include "Common.h"
#include "ndisapi.h"

class WinPkFilterDriver {
public:
    // Callback: packet data, length, outbound (true) or inbound (false)
    using PacketHandler = std::function<void(const char* packet, size_t length, bool outbound)>;

    WinPkFilterDriver();
    ~WinPkFilterDriver();

    // adapter_name is the NDIS internal name (e.g. \DEVICE\TCPIP_{...})
    bool start(const std::string& adapter_name, PacketHandler handler);
    void stop();

    // Send packet to adapter (injecting into the wire)
    bool send_to_adapter(const char* packet, size_t length);
    
    // Send packet to MSTCP (injecting into the local stack)
    bool send_to_mstcp(const char* packet, size_t length);

    bool get_adapter_mac(const std::string& adapter_name, uint8_t* mac);

    static std::vector<std::pair<std::string, std::string>> get_adapters();

private:
    void run();

    CNdisApi m_ndis_api;
    HANDLE m_adapter_handle;
    HANDLE m_wait_event;
    
    PacketHandler m_packet_handler;
    std::thread m_worker_thread;
    bool m_running;
};