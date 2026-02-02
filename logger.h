#pragma once
#include <string>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <cstdarg>
#include <vector>

// 4MB Ring Buffer
#define RING_BUFFER_SIZE (4 * 1024 * 1024)

class AsyncLogger {
public:
    static AsyncLogger& instance();
    void log(const char* fmt, ...);
    
private:
    AsyncLogger();
    ~AsyncLogger();
    void writer_loop();

    std::mutex m_mtx;
    std::condition_variable m_cv;
    
    // Ring Buffer Implementation
    std::vector<char> m_buffer;
    size_t m_write_idx;
    size_t m_read_idx;
    size_t m_size; // Size of buffer

    std::atomic<bool> m_running;
    std::thread m_writer_thread;
};