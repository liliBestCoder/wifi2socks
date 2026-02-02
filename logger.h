#pragma once
#include <string>
#include <mutex>
#include <deque>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <cstdarg>
#include <vector>

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
    std::deque<std::string> m_queue;
    std::atomic<bool> m_running;
    std::thread m_writer_thread;
};
