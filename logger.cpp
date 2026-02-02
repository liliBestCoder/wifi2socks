#include "logger.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <algorithm> // for std::min

AsyncLogger& AsyncLogger::instance() {
    static AsyncLogger inst;
    return inst;
}

AsyncLogger::AsyncLogger() 
    : m_running(true), m_write_idx(0), m_read_idx(0), m_size(RING_BUFFER_SIZE) {
    m_buffer.resize(m_size);
    m_writer_thread = std::thread(&AsyncLogger::writer_loop, this);
}

AsyncLogger::~AsyncLogger() {
    m_running = false;
    m_cv.notify_all();
    if (m_writer_thread.joinable()) m_writer_thread.join();
}

void AsyncLogger::log(const char* fmt, ...) {
    // 1. Format to stack buffer (Fast, no malloc)
    char tmp[4096];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);

    if (len <= 0) return;

    // 2. Critical Section: Copy to Ring Buffer
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        
        // Calculate free space
        // Formula: (read - write - 1 + size) % size
        // We reserve 1 byte to distinguish full from empty
        size_t free_space = (m_read_idx - m_write_idx - 1 + m_size) % m_size;
        
        // Need space for: Length Header (4 bytes) + String Data
        size_t needed = sizeof(int) + len;

        if (free_space < needed) {
            // Buffer Full: Drop this log to preserve system latency
            return; 
        }

        // A. Write Length Header
        int header_len = len;
        if (m_write_idx + sizeof(int) <= m_size) {
            memcpy(&m_buffer[m_write_idx], &header_len, sizeof(int));
        } else {
            // Wrap around for header
            size_t first = m_size - m_write_idx;
            memcpy(&m_buffer[m_write_idx], &header_len, first);
            memcpy(&m_buffer[0], ((char*)&header_len) + first, sizeof(int) - first);
        }
        m_write_idx = (m_write_idx + sizeof(int)) % m_size;

        // B. Write String Data
        if (m_write_idx + len <= m_size) {
            memcpy(&m_buffer[m_write_idx], tmp, len);
        } else {
            // Wrap around for data
            size_t first = m_size - m_write_idx;
            memcpy(&m_buffer[m_write_idx], tmp, first);
            memcpy(&m_buffer[0], tmp + first, len - first);
        }
        m_write_idx = (m_write_idx + len) % m_size;
    }
    
    m_cv.notify_one();
}

void AsyncLogger::writer_loop() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    
    // Local buffer for printing
    char out_buf[4096]; 

    while (m_running) {
        int len = 0;
        
        {
            std::unique_lock<std::mutex> lock(m_mtx);
            m_cv.wait(lock, [this]() { return m_read_idx != m_write_idx || !m_running; });
            
            if (!m_running && m_read_idx == m_write_idx) break;

            if (m_read_idx != m_write_idx) {
                // A. Read Length Header
                if (m_read_idx + sizeof(int) <= m_size) {
                    memcpy(&len, &m_buffer[m_read_idx], sizeof(int));
                } else {
                    size_t first = m_size - m_read_idx;
                    memcpy(&len, &m_buffer[m_read_idx], first);
                    memcpy(((char*)&len) + first, &m_buffer[0], sizeof(int) - first);
                }
                m_read_idx = (m_read_idx + sizeof(int)) % m_size;

                // Safety clamp
                if (len > sizeof(out_buf) - 1) len = sizeof(out_buf) - 1;

                // B. Read Data
                if (len > 0) {
                    if (m_read_idx + len <= m_size) {
                        memcpy(out_buf, &m_buffer[m_read_idx], len);
                    } else {
                        size_t first = m_size - m_read_idx;
                        memcpy(out_buf, &m_buffer[m_read_idx], first);
                        memcpy(out_buf + first, &m_buffer[0], len - first);
                    }
                    m_read_idx = (m_read_idx + len) % m_size;
                    out_buf[len] = '\0'; // Null terminate
                }
            }
        } // Unlock immediately

        if (len > 0) {
            // IO operation outside lock
            fwrite(out_buf, 1, len, stdout);
        }
    }
}