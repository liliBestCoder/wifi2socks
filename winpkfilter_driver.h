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
    void send_ipv6_tcp_rst(const char* original_packet, size_t length);
    bool get_adapter_mac(const std::string& adapter_name, uint8_t* mac);
    void send_dhcp_response(const uint8_t* client_mac, const uint32_t src_ip, const DhcpResponse& dhcp_r, const uint8_t* m_adapter_mac);

    static std::vector<std::pair<std::string, std::string>> get_adapters();

private:
    void reader_loop();
    void worker_loop(unsigned int worker_id);

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

    static const int QUEUE_SIZE = 4096;
    struct WorkerQueue {
        // Prevent False Sharing: keep producer and consumer indices on separate cache lines
        alignas(64) std::atomic<uint32_t> head{ 0 };
        alignas(64) std::atomic<uint32_t> tail{ 0 };
        
        // Ensure data array starts on a new cache line as well
        alignas(64) PINTERMEDIATE_BUFFER ring[QUEUE_SIZE];
        
        std::mutex mtx;
        std::condition_variable cv;

        WorkerQueue() : head(0), tail(0) {}

        bool push(PINTERMEDIATE_BUFFER buf) {
            uint32_t h = head.load(std::memory_order_relaxed);
            uint32_t t = tail.load(std::memory_order_acquire);
            uint32_t next = (h + 1) % QUEUE_SIZE;
            if (next == t) return false; // Full
            ring[h] = buf;
            head.store(next, std::memory_order_release);
            return true;
        }

        PINTERMEDIATE_BUFFER pop() {
            uint32_t t = tail.load(std::memory_order_relaxed);
            uint32_t h = head.load(std::memory_order_acquire);
            if (h == t) return nullptr; // Empty
            PINTERMEDIATE_BUFFER buf = ring[t];
            tail.store((t + 1) % QUEUE_SIZE, std::memory_order_release);
            return buf;
        }

        size_t pop_batch(PINTERMEDIATE_BUFFER* p, size_t count) {
            uint32_t t = tail.load(std::memory_order_relaxed);
            uint32_t h = head.load(std::memory_order_acquire);
            if (h == t) return 0;
            size_t available = (h > t) ? (h - t) : (QUEUE_SIZE - t + h);
            size_t actual = (std::min)(count, available);
            for (size_t i = 0; i < actual; ++i) {
                p[i] = ring[t];
                t = (t + 1) % QUEUE_SIZE;
            }
            tail.store(t, std::memory_order_release);
            return actual;
        }

        size_t size() const {
            uint32_t h = head.load(std::memory_order_relaxed);
            uint32_t t = tail.load(std::memory_order_relaxed);
            if (h >= t) return h - t;
            return QUEUE_SIZE - (t - h);
        }
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