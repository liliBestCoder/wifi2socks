#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <cstdint>
#include <mutex>
#include <deque>
#include <vector>
#include <thread>
#include <condition_variable>
#include <atomic>

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
    
    // Asynchronous Write Queue
    std::mutex m_queue_mtx;
    std::deque<std::vector<uint8_t>> m_write_queue;
    std::condition_variable m_cv;
    std::atomic<bool> m_running;
    std::thread m_writer_thread;
};
