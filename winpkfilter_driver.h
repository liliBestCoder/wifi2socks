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

// Enable Jumbo Frame support to ensure buffer size is 9014 (safe for all DLL versions)
#ifndef JUMBO_FRAME_SUPPORTED
#define JUMBO_FRAME_SUPPORTED 1
#endif

// WinPkFilter SDK headers (Original ones restored)
#include "Common.h"
#include "ndisapi.h"
#include "packet_pool.h"

// Combined flags for convenience if not in older Common.h
#ifndef MSTCP_FLAG_TUNNEL
#define MSTCP_FLAG_TUNNEL (0x00000001 | 0x00000002)
#endif
#ifndef MSTCP_FLAG_SENT_RECEIVE
#define MSTCP_FLAG_SENT_RECEIVE (0x00000001 | 0x00000002)
#endif

class WinPkFilterDriver {

public:

    struct Packet {

        RawPacketPtr data;

        bool outbound;

    };

    using PacketHandler = std::function<void(const char* packet, size_t length, bool outbound)>;

    using BatchPacketHandler = std::function<void(std::vector<Packet>&& packets)>;



    WinPkFilterDriver();

    ~WinPkFilterDriver();



    bool start(const std::string& adapter_name, PacketHandler handler, std::function<void()> on_before_batch = nullptr, std::function<void()> on_after_batch = nullptr);

    bool start_batch(const std::string& adapter_name, BatchPacketHandler handler);

    void stop();



    bool send_to_adapter(const char* packet, size_t length);
    bool send_packets_to_adapter(std::vector<Packet>&& packets);
    bool send_to_mstcp(const char* packet, size_t length);
    bool get_adapter_mac(const std::string& adapter_name, uint8_t* mac);

    static std::vector<std::pair<std::string, std::string>> get_adapters();

private:
    void run();
    void tx_run();

    CNdisApi m_ndis_api;
    HANDLE m_adapter_handle;
    HANDLE m_wait_event;
    
    PacketHandler m_packet_handler;
    BatchPacketHandler m_batch_handler;
    std::function<void()> m_on_before_batch;
    std::function<void()> m_on_after_batch;

    std::thread m_worker_thread;
    std::thread m_tx_thread;
    bool m_running;
    bool m_tx_running;

    HANDLE m_tx_event;
    std::mutex m_tx_mtx;
    std::vector<std::vector<Packet>> m_tx_queue;

    static const int BATCH_SIZE = 512;
    PETH_M_REQUEST m_read_request;
    PINTERMEDIATE_BUFFER m_read_buffers[BATCH_SIZE];
    
    PETH_M_REQUEST m_write_request;
    PETH_M_REQUEST m_mstcp_request;
    PINTERMEDIATE_BUFFER m_write_buffers[BATCH_SIZE];
    
    INTERMEDIATE_BUFFER* m_send_buffer;
    std::mutex m_send_mutex;
    std::mutex m_write_mutex;

    uint8_t m_adapter_mac[6];
    uint32_t m_gateway_ip;
};
