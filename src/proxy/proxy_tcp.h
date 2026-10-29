#pragma once

#include <winsock2.h>
#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <deque>
#include <mutex>
#include <unordered_set>

#include "worker.h"
#include "nat_manager.h"

class ProxyTCP : public std::enable_shared_from_this<ProxyTCP> {
public:
    struct IoBuffer {
        OVERLAPPED overlapped;
        IO_TYPE type; // Must be IO_PROXY_BUFFER to match worker check

        WSABUF wsa_buf;    // For WSARecv/WSASend
        size_t capacity;
        size_t total_bytes; // Bytes read (valid data)
        size_t written_bytes; // Bytes written (progress)

        enum State { IO_READING, IO_READY, IO_WRITING, IO_COMPLETED, IO_DROPPED, IO_EOF } state;

        std::function<void(DWORD, int)> on_complete;
        SOCKET socket; // The socket this op is associated with

        // Batching support (Gather Write)
        IoBuffer* next_in_batch{ nullptr };
        DWORD flags{ 0 }; // Must be persistent for async IO

        uint8_t buffer[131072]; // 128KB inline buffer - MOVED TO THE END for safety

        IoBuffer() : type(IO_PROXY_BUFFER), capacity(sizeof(buffer)),
            total_bytes(0), written_bytes(0), state(IO_READING),
            socket(INVALID_SOCKET), flags(0) {
            memset(&overlapped, 0, sizeof(OVERLAPPED));
            wsa_buf.buf = (char*)buffer;
            wsa_buf.len = (ULONG)capacity;
        }

        ~IoBuffer() {
            // buffer is now inline, no need to delete[]
        }
    };

    // Constructor takes the already-accepted client socket and its original destination.
    ProxyTCP(SOCKET client_socket, OriginalDestination dest);
    ~ProxyTCP();

    // Starts the proxy session.
    void start();

    // Callback for Worker to notify IO completion
    void on_io_complete(IoBuffer* buffer, DWORD bytes_transferred, int error);

private:
    void connect_remote();
    void on_remote_connect(); // Keep for async connect

    // The core function to gracefully close the session.
    void close_session();
    void close_session_internal(); // Internal version without lock

    enum State {
        INITIAL,
        CONNECTING,
        AWAITING_CONNECT_RESPONSE,
        ESTABLISHED,
        CLOSING
    };

    std::atomic<State> m_state;
    SOCKET m_client_socket;
    SOCKET m_remote_socket;
    OriginalDestination m_original_dest;
    uint64_t m_nat_key{ 0 };
    bool m_has_nat_key{ false };

    std::vector<uint8_t> m_initial_buffer; // Buffer for data received before ESTABLISHED (still needed for handshake parsing)
    std::string m_detected_domain;
    std::string m_initial_http_first_line;
    std::string m_dns_hint_domain;
    std::string m_probe_class;
    std::string m_probe_proto;
    bool m_is_direct;
    bool m_is_netcheck_flow{ false };
    bool m_is_youtube_flow{ false };
    bool m_is_http_probe_miss{ false };
    uint64_t m_session_id{ 0 };
    uint64_t m_start_time{ 0 };
    uint64_t m_connect_start_time{ 0 };
    uint64_t m_remote_connected_time{ 0 };
    uint64_t m_proxy_connect_ok_time{ 0 };
    uint64_t m_first_client_byte_time{ 0 };
    uint64_t m_first_remote_byte_time{ 0 };
    uint64_t m_first_remote_payload_time{ 0 };
    uint64_t m_last_client_payload_time{ 0 };
    uint64_t m_last_remote_payload_time{ 0 };
    uint64_t m_last_probe_stat_time{ 0 };
    uint64_t m_last_probe_c2r_bytes{ 0 };
    uint64_t m_last_probe_r2c_bytes{ 0 };
    uint64_t m_last_youtube_stat_time{ 0 };
    uint64_t m_last_youtube_c2r_bytes{ 0 };
    uint64_t m_last_youtube_r2c_bytes{ 0 };
    std::atomic<uint64_t> m_client_to_remote_bytes{ 0 };
    std::atomic<uint64_t> m_remote_to_client_bytes{ 0 };
    std::string m_close_reason;

    // Handlers
    void handle_client_read_complete(IoBuffer* buffer);
    void handle_remote_read_complete(IoBuffer* buffer);
    void handle_client_write_complete(IoBuffer* buffer);
    void handle_remote_write_complete(IoBuffer* buffer);

    void process_write_queue(SOCKET socket);
    void post_reads(SOCKET socket);
    void set_close_reason_unlocked(const std::string& reason);
    void log_probe_unlocked(const char* stage, int error = 0, const char* detail = nullptr);

    // Write Queues (for Backpressure)
    std::deque<IoBuffer*> m_client_write_queue;
    std::deque<IoBuffer*> m_remote_write_queue;

    // Write In-flight tracking (Concurrency Control)
    std::atomic<int> m_client_inflight_write_count{ 0 };
    std::atomic<int> m_remote_inflight_write_count{ 0 };

    std::mutex m_mutex; // General lock for queues

    // Pending Read Counts (for Concurrency Control)
    std::atomic<int> m_client_pending_read_count{ 0 };
    std::atomic<int> m_remote_pending_read_count{ 0 };

    // Queue Sizing for Backpressure
    size_t m_client_write_queue_size{ 0 };
    size_t m_remote_write_queue_size{ 0 };

    static size_t high_water_mark();
    static size_t low_water_mark();
    static const int MAX_PENDING_READS = 4;
    static const int MAX_PENDING_WRITES = 4;
    static const int MAX_GATHER_BATCH = 8;

    // Flow control flags
    bool m_remote_read_paused{ false };
    bool m_client_read_paused{ false };

    // Graceful shutdown flags
    std::atomic<bool> m_client_eof{ false };
    std::atomic<bool> m_remote_eof{ false };
    std::atomic<bool> m_client_fin_sent{ false };
    std::atomic<bool> m_remote_fin_sent{ false };

    // Activity tracking to prevent zombie sessions
    std::atomic<uint64_t> m_last_access_time{ 0 };
    std::atomic<uint64_t> m_half_close_start_time{ 0 };
    static const uint64_t IDLE_TIMEOUT_MS = 600000; // 10 minutes
    static const uint64_t FIN_WAIT_TIMEOUT_MS = 10000; // Short grace period after either side starts closing

    // Handshake special handling
    std::vector<char> m_proxy_response_buffer;

    // Static registry for periodic cleanup
    static std::mutex g_sessions_mtx;
    static std::vector<std::weak_ptr<ProxyTCP>> g_sessions;
    static std::atomic<size_t> g_client_queue_bytes;
    static std::atomic<size_t> g_remote_queue_bytes;
    static std::atomic<int> g_pressure_level;
    static std::atomic<uint64_t> g_pressure_reject_tcp;
public:
    static void check_all_timeouts();
    static void log_global_stats();
    static int pressure_level();
    static bool pressure_high();
    static bool pressure_critical();
private:

    void add_client_queue_bytes(size_t bytes);
    void sub_client_queue_bytes(size_t bytes);
    void add_remote_queue_bytes(size_t bytes);
    void sub_remote_queue_bytes(size_t bytes);
    void reset_queue_pressure_bytes();

    // Cleanup
    void free_buffer(IoBuffer* buffer);
    bool detach_buffer(IoBuffer* buffer);
    bool detach_buffer_if_releasable(IoBuffer* buffer);
    void recycle_buffer(IoBuffer* buffer);
    IoBuffer* alloc_buffer(size_t size = 8192);

    std::mutex m_buffer_mutex;
    std::unordered_set<IoBuffer*> m_live_buffers;
};
