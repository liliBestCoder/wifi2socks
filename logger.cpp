#define _CRT_SECURE_NO_WARNINGS
#include "logger.h"
#include <cstdio>
#include <cstdarg>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <vector>

AsyncLogger& AsyncLogger::instance() {
    static AsyncLogger inst;
    return inst;
}

AsyncLogger::AsyncLogger() : m_running(true), m_min_level(LOG_LEVEL_INFO) {
    m_queue.reserve(256); // Pre-allocate some space
    m_thread = std::thread(&AsyncLogger::worker_loop, this);
}

AsyncLogger::~AsyncLogger() {
    m_running = false;
    m_cv.notify_one();
    if (m_thread.joinable()) m_thread.join();
    if (m_file.is_open()) m_file.close();
}

void AsyncLogger::init(const std::string& filename) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) m_file.close();
    m_file.open(filename, std::ios::app);
}

void AsyncLogger::log(LogLevel level, const char* format, ...) {
    if (level < m_min_level) return;

    LogItem item;
    item.level = level;
    item.timestamp = std::chrono::system_clock::now();

    char msg_buf[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(msg_buf, sizeof(msg_buf), format, args);
    va_end(args);
    item.message = msg_buf;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.size() < 10000) { // Limit queue size
            m_queue.push_back(std::move(item));
        }
    }
    m_cv.notify_one();
}

void AsyncLogger::worker_loop() {
    std::vector<LogItem> local_queue;
    local_queue.reserve(256);

    while (m_running || !m_queue.empty()) {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this] { return !m_queue.empty() || !m_running; });
            
            if (m_queue.empty() && !m_running) break;
            
            m_queue.swap(local_queue);
        }

        for (const auto& item : local_queue) {
            auto time_t_now = std::chrono::system_clock::to_time_t(item.timestamp);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(item.timestamp.time_since_epoch()) % 1000;

            std::tm tm_now;
            localtime_s(&tm_now, &time_t_now);

            const char* level_str = "[UNKNOWN]";
            switch (item.level) {
                case LOG_LEVEL_DEBUG: level_str = "[DEBUG]"; break;
                case LOG_LEVEL_INFO:  level_str = "[INFO] "; break;
                case LOG_LEVEL_WARN:  level_str = "[WARN] "; break;
                case LOG_LEVEL_ERROR: level_str = "[ERROR]"; break;
            }

            char time_buf[64];
            std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_now);

            // Print formatted log to string first
            char final_msg[4096];
            int len = snprintf(final_msg, sizeof(final_msg), "[%s.%03lld] %s %s\n", 
                               time_buf, (long long)ms.count(), level_str, item.message.c_str());

            if (len > 0) {
                // Print to Console
                fputs(final_msg, stdout);
                
                // Write to File
                if (m_file.is_open()) {
                    m_file.write(final_msg, len);
                }
            }
        }
        
        // Batch flush
        if (m_file.is_open()) {
            m_file.flush();
        }
        
        local_queue.clear();
    }
}
