#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <cstdint>
#include <mutex>
#include <vector>
#include <thread>
#include <condition_variable>
#include <atomic>

// 16MB Ring Buffer for Network Packets
// Network traffic is bursty, so we need a larger buffer than logs.
#define TAP_RING_BUFFER_SIZE (16 * 1024 * 1024)

class TapDriver {
public:
    static TapDriver& instance();
    
    bool init(const char* device_guid);
    void send_async(const uint8_t* buf, int len);
    HANDLE handle() const { return m_tap; }
    
    // Config
    static const uint8_t TAP_MAC[6];
    
private:
    TapDriver();
    ~TapDriver();
    void writer_loop();

    HANDLE m_tap;
    
    // Ring Buffer Implementation
    std::mutex m_mtx;
    std::condition_variable m_cv;
    
    std::vector<char> m_buffer;
    size_t m_write_idx;
    size_t m_read_idx;
    size_t m_size;

    std::atomic<bool> m_running;
    std::thread m_writer_thread;
};