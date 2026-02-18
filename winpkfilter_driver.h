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
#include <condition_variable>
#include <list>

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
    bool send_to_mstcp(const char* packet, size_t length);
    bool get_adapter_mac(const std::string& adapter_name, uint8_t* mac);

    static std::vector<std::pair<std::string, std::string>> get_adapters();

private:
    void run();
    void worker_loop(unsigned int worker_id);

    CNdisApi m_ndis_api;
    HANDLE m_adapter_handle;
    HANDLE m_wait_event;
    
    PacketHandler m_packet_handler;
    BatchPacketHandler m_batch_handler;
    std::function<void()> m_on_before_batch;
    std::function<void()> m_on_after_batch;

    std::thread m_reader_thread;
    bool m_running;

    // --- New members for multi-threading ---

    unsigned int m_num_workers;
    std::vector<std::thread> m_worker_threads;

    // Struct for packets in the worker queues
    struct QueuedPacket {
        INTERMEDIATE_BUFFER* buffer;
    };

    // Each worker has its own queue to ensure packet order for a flow
    struct WorkerQueue {
        std::list<QueuedPacket> packets;
        std::mutex mtx;
        std::condition_variable cv;
    };
    std::vector<WorkerQueue> m_worker_queues;

    // Struct for processed packets ready to be written back
    enum class PacketDestination { TO_ADAPTER, TO_MSTCP };
    struct ProcessedPacket {
        INTERMEDIATE_BUFFER* buffer;
        PacketDestination destination;
    };
    
    // A single queue for all workers to put their results
    struct ResultQueue {
        std::list<ProcessedPacket> packets;
        std::mutex mtx;
        std::condition_variable cv;
    } m_results_queue;
    
    // --- End of new members ---

    static const int BATCH_SIZE = 512;
    PETH_M_REQUEST m_read_request;
    PINTERMEDIATE_BUFFER m_read_buffers[BATCH_SIZE];
    
    PETH_M_REQUEST m_write_request;
    PETH_M_REQUEST m_mstcp_request;
    
    INTERMEDIATE_BUFFER* m_send_buffer;
    std::mutex m_send_mutex;
    std::mutex m_write_mutex;

    uint8_t m_adapter_mac[6];
    uint32_t m_gateway_ip;
};