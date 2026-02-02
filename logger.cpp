#include "logger.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

AsyncLogger& AsyncLogger::instance() {
    static AsyncLogger inst;
    return inst;
}

AsyncLogger::AsyncLogger() : m_running(true) {
    m_writer_thread = std::thread(&AsyncLogger::writer_loop, this);
}

AsyncLogger::~AsyncLogger() {
    m_running = false;
    m_cv.notify_all();
    if (m_writer_thread.joinable()) m_writer_thread.join();
}

void AsyncLogger::log(const char* fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    {
        std::lock_guard<std::mutex> lock(m_mtx);
        if (m_queue.size() < 5000) { 
            m_queue.emplace_back(buf);
        }
    }
    m_cv.notify_one();
}

void AsyncLogger::writer_loop() {
    // Lower priority for logging thread to avoid impacting networking
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    
    while (m_running) {
        std::string msg;
        {
            std::unique_lock<std::mutex> lock(m_mtx);
            m_cv.wait(lock, [this]() { return !m_queue.empty() || !m_running; });
            
            if (!m_running && m_queue.empty()) break;
            
            if (!m_queue.empty()) {
                msg = std::move(m_queue.front());
                m_queue.pop_front();
            }
        }
        
        if (!msg.empty()) {
            printf("%s", msg.c_str());
        }
    }
}
