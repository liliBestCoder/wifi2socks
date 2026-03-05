#pragma once
#include <string>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <cstdarg>
#include <vector>
#include <fstream>
#include <chrono>

enum LogLevel {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_NONE = 99
};

struct LogItem {
    LogLevel level;
    std::chrono::system_clock::time_point timestamp;
    std::string message;
};

class AsyncLogger {
public:
    static AsyncLogger& instance();
    
    // Initialize log file
    void init(const std::string& filename);
    
    // Log function with level
    void log(LogLevel level, const char* fmt, ...);
    
    // Set minimum log level
    void set_level(LogLevel level) { m_min_level = level; }

private:
    AsyncLogger();
    ~AsyncLogger();
    void worker_loop();

    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<LogItem> m_queue;
    std::atomic<bool> m_running;
    std::thread m_thread;
    std::ofstream m_file;
    
    std::atomic<LogLevel> m_min_level{LOG_LEVEL_INFO}; // Default level
};
