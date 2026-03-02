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
#include <memory>
#include <atomic>
#include <chrono>

#ifndef JUMBO_FRAME_SUPPORTED
#define JUMBO_FRAME_SUPPORTED 1
#endif

// WinPkFilter SDK headers
#include "Common.h"
#include "ndisapi.h"
#include "packet_pool.h"
#include "dhcp_server.h"

// Combined flags definitions if not present in Common.h
#ifndef MSTCP_FLAG_TUNNEL
#define MSTCP_FLAG_TUNNEL 0x00000002
#endif
#ifndef MSTCP_FLAG_SENT_RECEIVE
#define MSTCP_FLAG_SENT_RECEIVE 0x00000001
#endif
#ifndef MSTCP_FLAG_RECV_TUNNEL
#define MSTCP_FLAG_RECV_TUNNEL 0x00000002
#endif

class WinPkFilterDriver {

public:

    struct Packet {
        RawPacketPtr data;
        bool outbound;
        // Explicit constructor to solve C2661
        Packet(RawPacketPtr d, bool o) : data(std::move(d)), outbound(o) {}
        Packet() : outbound(false) {}
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
    void send_dhcp_response(const uint8_t* client_mac, const uint32_t src_ip, const DhcpResponse& dhcp_r, const uint8_t* m_adapter_mac);

    static std::vector<std::pair<std::string, std::string>> get_adapters();

private:
    void reader_loop();
    void worker_loop(unsigned int worker_id);
    void adapter_sender_loop(unsigned int worker_id);
    void stack_sender_loop(unsigned int worker_id);

    CNdisApi m_ndis_api;
    HANDLE m_adapter_handle;
    HANDLE m_wait_event;
    
    PacketHandler m_packet_handler;
    BatchPacketHandler m_batch_handler;
    std::function<void()> m_on_before_batch;
    std::function<void()> m_on_after_batch;

    std::thread m_reader_thread;
    std::atomic<bool> m_running;

    // --- Multi-threading members ---

    unsigned int m_num_workers;
    std::vector<std::thread> m_worker_threads;

    struct QueuedPacket {
        PINTERMEDIATE_BUFFER buffer;
    };

    // --- High Performance Lock-free SPSC Queue ---
    template <typename T, size_t Size>
    class SPSCQueue {
    public:
        static_assert((Size & (Size - 1)) == 0, "Size must be power of 2");
        bool push(T item) {
            size_t head = m_head.load(std::memory_order_relaxed);
            if (head - m_tail.load(std::memory_order_acquire) == Size) return false;
            m_buffer[head & (Size - 1)] = std::move(item);
            m_head.store(head + 1, std::memory_order_release);
            return true;
        }
        bool pop(T& item) {
            size_t tail = m_tail.load(std::memory_order_relaxed);
            if (tail == m_head.load(std::memory_order_acquire)) return false;
            item = std::move(m_buffer[tail & (Size - 1)]);
            m_tail.store(tail + 1, std::memory_order_release);
            return true;
        }
    private:
        alignas(64) T m_buffer[Size];
        alignas(64) std::atomic<size_t> m_head{0};
        alignas(64) std::atomic<size_t> m_tail{0};
    };

    struct WorkerQueue {
        // Input from Reader (keeping mutex for now as requested no change to reader_loop)
        std::list<QueuedPacket> packets;
        std::mutex mtx;
        std::condition_variable cv;

        // Output to Senders (SPSC - lock-free)
        SPSCQueue<PINTERMEDIATE_BUFFER, 1024> to_adapter_q;
        SPSCQueue<PINTERMEDIATE_BUFFER, 1024> to_stack_q;

        std::unique_ptr<std::thread> adapter_sender;
        std::unique_ptr<std::thread> stack_sender;
    };
    // Use unique_ptr to handle mutex non-copyable issue (C2280)
    std::vector<std::unique_ptr<WorkerQueue>> m_worker_queues;

    // Statistics counters (Pure atomic, no logging overhead in worker loop)
    std::atomic<uint64_t> m_stat_dl_pkts{0};
    std::atomic<uint64_t> m_stat_dl_bytes{0};
    std::atomic<uint64_t> m_stat_ul_pkts{0};
    std::atomic<uint64_t> m_stat_ul_bytes{0};
    std::atomic<uint64_t> m_stat_work_time_us{0};
    std::chrono::steady_clock::time_point m_last_stat_time;

    // --- End of new members ---

    static const int BATCH_SIZE = 512;
    PETH_M_REQUEST m_read_request;
    PINTERMEDIATE_BUFFER m_read_buffers[BATCH_SIZE];
    
    INTERMEDIATE_BUFFER* m_send_buffer;
    std::mutex m_send_mutex;
    std::mutex m_write_mutex;

    uint8_t m_adapter_mac[6];
    uint32_t m_gateway_ip;
};