#include "logger.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <algorithm> 

AsyncLogger& AsyncLogger::instance() {
    static AsyncLogger inst;
    return inst;
}

AsyncLogger::AsyncLogger()
    : m_running(true), m_write_idx(0), m_read_idx(0), m_size(RING_BUFFER_SIZE) {

    m_file_ptr = _fsopen("wifi2socks.log", "a", _SH_DENYNO);

    if (m_file_ptr == nullptr) {
        // 如果打开失败，尝试获取绝对路径打印出来，方便排查位置问题
        char full_path[MAX_PATH];
        _fullpath(full_path, "wifi2socks.log", MAX_PATH);
        printf("[Logger] Error: Cannot open/create log file at: %s\n", full_path);
    }
    else {
        printf("[Logger] Log file initialized with shared mode.\n");
    }

    m_buffer.resize(m_size);
    m_writer_thread = std::thread(&AsyncLogger::writer_loop, this);
}

AsyncLogger::~AsyncLogger() {
    m_running = false;
    m_cv.notify_all();
    if (m_writer_thread.joinable()) m_writer_thread.join();

    // 2. 析构时关闭文件
    if (m_file_ptr) {
        fclose(m_file_ptr);
        m_file_ptr = nullptr;
    }
}

void AsyncLogger::log(const char* fmt, ...) {
    char tmp[4096];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);

    if (len <= 0) return;

    {
        std::lock_guard<std::mutex> lock(m_mtx);

        size_t free_space = (m_read_idx - m_write_idx - 1 + m_size) % m_size;
        size_t needed = sizeof(int) + len;

        if (free_space < needed) {
            return; // 缓冲区满，丢弃日志
        }

        // A. 写入长度头
        int header_len = len;
        if (m_write_idx + sizeof(int) <= m_size) {
            memcpy(&m_buffer[m_write_idx], &header_len, sizeof(int));
        }
        else {
            size_t first = m_size - m_write_idx;
            memcpy(&m_buffer[m_write_idx], &header_len, first);
            memcpy(&m_buffer[0], ((char*)&header_len) + first, sizeof(int) - first);
        }
        m_write_idx = (m_write_idx + sizeof(int)) % m_size;

        // B. 写入字符串数据
        if (m_write_idx + len <= m_size) {
            memcpy(&m_buffer[m_write_idx], tmp, len);
        }
        else {
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

    char out_buf[4096];

    while (m_running) {
        int len = 0;

        {
            std::unique_lock<std::mutex> lock(m_mtx);
            m_cv.wait(lock, [this]() { return m_read_idx != m_write_idx || !m_running; });

            if (!m_running && m_read_idx == m_write_idx) break;

            if (m_read_idx != m_write_idx) {
                // A. 读取长度头
                if (m_read_idx + sizeof(int) <= m_size) {
                    memcpy(&len, &m_buffer[m_read_idx], sizeof(int));
                }
                else {
                    size_t first = m_size - m_read_idx;
                    memcpy(&len, &m_buffer[m_read_idx], first);
                    memcpy(((char*)&len) + first, &m_buffer[0], sizeof(int) - first);
                }
                m_read_idx = (m_read_idx + sizeof(int)) % m_size;

                if (len > sizeof(out_buf) - 1) len = sizeof(out_buf) - 1;

                // B. 读取数据
                if (len > 0) {
                    if (m_read_idx + len <= m_size) {
                        memcpy(out_buf, &m_buffer[m_read_idx], len);
                    }
                    else {
                        size_t first = m_size - m_read_idx;
                        memcpy(out_buf, &m_buffer[m_read_idx], first);
                        memcpy(out_buf + first, &m_buffer[0], len - first);
                    }
                    m_read_idx = (m_read_idx + len) % m_size;
                    out_buf[len] = '\0';
                }
            }
        }

        if (len > 0) {
            // 3. 同时输出到屏幕和文件
            // 输出到屏幕 (stdout)
            fwrite(out_buf, 1, len, stdout);
            fflush(stdout);

            // 输出到文件
            if (m_file_ptr) {
                fwrite(out_buf, 1, len, m_file_ptr);
                // 关键：fflush 确保 HTTP 接口能通过 seekg 读到实时更新
                fflush(m_file_ptr);
            }
        }
    }
}