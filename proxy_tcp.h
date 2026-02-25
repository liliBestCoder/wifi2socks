#pragma once

#include <winsock2.h>
#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <deque>
#include <mutex>

#include "worker.h"
#include "nat_manager.h"

class ProxyTCP : public std::enable_shared_from_this<ProxyTCP> {
public:
    struct IoBuffer {
        OVERLAPPED overlapped;
        IO_TYPE type; // Must be IO_PROXY_BUFFER to match worker check

        uint8_t buffer[131072]; // 128KB inline buffer to reduce fragmentation and overhead
        WSABUF wsa_buf;    // For WSARecv/WSASend

        size_t capacity;
        size_t total_bytes; // Bytes read (valid data)
        size_t written_bytes; // Bytes written (progress)

        enum State { IO_READING, IO_READY, IO_WRITING, IO_COMPLETED, IO_DROPPED } state;

        std::function<void(DWORD, int)> on_complete;
        SOCKET socket; // The socket this op is associated with

        // Batching support (Gather Write)
        IoBuffer* next_in_batch{ nullptr };
        DWORD flags{ 0 }; // Must be persistent for async IO

        IoBuffer() : type(IO_PROXY_BUFFER), capacity(sizeof(buffer)),
            total_bytes(0), written_bytes(0), state(IO_READING),
            socket(INVALID_SOCKET), flags(0) {
            memset(&overlapped, 0, sizeof(OVERLAPPED));
            memset(buffer, 0, sizeof(buffer));
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

    std::vector<uint8_t> m_initial_buffer; // Buffer for data received before ESTABLISHED (still needed for handshake parsing)
    std::string m_detected_domain;
    bool m_is_direct;

    // Handlers
    void handle_client_read_complete(IoBuffer* buffer);
    void handle_remote_read_complete(IoBuffer* buffer);
    void handle_client_write_complete(IoBuffer* buffer);
    void handle_remote_write_complete(IoBuffer* buffer);

    void process_write_queue(SOCKET socket);
    void post_reads(SOCKET socket);

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

    // Flow control watermarks (Optimized for high speed)
    static const size_t HIGH_WATER_MARK = 32 * 1024 * 1024; // 32MB - 提高水线以支持更高速度
    static const size_t LOW_WATER_MARK = 8 * 1024 * 1024;  // 8MB
    static const int MAX_PENDING_READS = 8; // 增加预读数量
    static const int MAX_PENDING_WRITES = 16; // 增加并发写入数，提高吞吐量
    static const int MAX_GATHER_BATCH = 32;  // 增加单次 WSASend 的批处理数量

    // Flow control flags
    bool m_remote_read_paused{ false };
    bool m_client_read_paused{ false };

    // Graceful shutdown flags
    std::atomic<bool> m_client_eof{ false };
    std::atomic<bool> m_remote_eof{ false };
    std::atomic<bool> m_client_fin_sent{ false };
    std::atomic<bool> m_remote_fin_sent{ false };

    // 性能统计
    uint64_t m_total_bytes_sent{ 0 };
    uint64_t m_total_bytes_received{ 0 };
    DWORD m_start_time{ 0 };

    // Handshake special handling
    std::vector<char> m_proxy_response_buffer;

    // Cleanup
    void free_buffer(IoBuffer* buffer);
    IoBuffer* alloc_buffer(size_t size = 8192);
};
