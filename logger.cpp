#define _CRT_SECURE_NO_WARNINGS
#include "logger.h"
#include <iostream>
#include <cstdarg>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

AsyncLogger& AsyncLogger::instance() {
    static AsyncLogger inst;
    return inst;
}

// Default to INFO as requested
AsyncLogger::AsyncLogger() : m_running(true), m_min_level(LOG_LEVEL_INFO) {
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

    // Get current time
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    
    std::tm tm_now;
    localtime_s(&tm_now, &time_t_now);

    // Map LogLevel to String
    const char* level_str = "[UNKNOWN]";
    switch (level) {
        case LOG_LEVEL_DEBUG: level_str = "[DEBUG]"; break;
        case LOG_LEVEL_INFO:  level_str = "[INFO] "; break;
        case LOG_LEVEL_WARN:  level_str = "[WARN] "; break;
        case LOG_LEVEL_ERROR: level_str = "[ERROR]"; break;
    }

    char time_buf[64];
    std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_now);

    char msg_buf[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(msg_buf, sizeof(msg_buf), format, args);
    va_end(args);

    std::stringstream ss;
    // Format: [Time.ms] [Level] Message
    ss << "[" << time_buf << "." << std::setfill('0') << std::setw(3) << ms.count() << "] " 
       << level_str << " " << msg_buf;

    std::string final_msg = ss.str();

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push(std::move(final_msg));
    }
    m_cv.notify_one();
}

void AsyncLogger::worker_loop() {
    while (m_running) {
        std::string msg;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this] { return !m_queue.empty() || !m_running; });
            if (!m_running && m_queue.empty()) break;
            if (m_queue.empty()) continue;
            msg = std::move(m_queue.front());
            m_queue.pop();
        }

        // Print to Console (stdout)
        printf("%s\n", msg.c_str());
        
        // Write to File
        if (m_file.is_open()) {
            m_file << msg << std::endl;
        }
    }
}
