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
        // �����ʧ�ܣ����Ի�ȡ����·����ӡ�����������Ų�λ������
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

    // 2. ����ʱ�ر��ļ�
    if (m_file_ptr) {
        fclose(m_file_ptr);
        m_file_ptr = nullptr;
    }
}

void AsyncLogger::log(const char* fmt, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char time_str[32];
    sprintf_s(time_str, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    char tmp[4096];
    strcpy_s(tmp, time_str);
    int time_len = (int)strlen(time_str);

    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(tmp + time_len, sizeof(tmp) - time_len, fmt, args);
    va_end(args);

    if (len <= 0) return;
    len += time_len;

    {
        std::lock_guard<std::mutex> lock(m_mtx);

        size_t free_space = (m_read_idx - m_write_idx - 1 + m_size) % m_size;
        size_t needed = sizeof(int) + len;

        if (free_space < needed) {
            return; // ����������������־
        }

        // A. д�볤��ͷ
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

        // B. д���ַ�������
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
                // A. ��ȡ����ͷ
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

                // B. ��ȡ����
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
            // 3. ͬʱ�������Ļ���ļ�
            // �������Ļ (stdout)
            fwrite(out_buf, 1, len, stdout);
            fflush(stdout);

            // ������ļ�
            if (m_file_ptr) {
                fwrite(out_buf, 1, len, m_file_ptr);
                // �ؼ���fflush ȷ�� HTTP �ӿ���ͨ�� seekg ����ʵʱ����
                fflush(m_file_ptr);
            }
        }
    }
}