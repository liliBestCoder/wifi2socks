#include "tap_driver.h"
#include "app_config.h"
#include "traffic_manager.h"
#include <cstdio>
#include <winioctl.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

uint8_t TapDriver::TAP_MAC[6] = { 0x00, 0xFF, 0x92, 0xEA, 0x69, 0x5C };

static void parse_mac(const std::string& str, uint8_t* mac) {
    unsigned int bytes[6];
    if (sscanf_s(str.c_str(), "%x:%x:%x:%x:%x:%x", 
        &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) == 6) {
        for (int i=0; i<6; ++i) mac[i] = (uint8_t)bytes[i];
    }
}

TapDriver& TapDriver::instance() {
    static TapDriver inst;
    return inst;
}

TapDriver::TapDriver() 
    : m_tap(INVALID_HANDLE_VALUE), m_running(true), 
      m_write_idx(0), m_read_idx(0), m_size(TAP_RING_BUFFER_SIZE) {
    parse_mac(g_config.tap_mac, TAP_MAC);
    m_buffer.resize(m_size);
    m_writer_thread = std::thread(&TapDriver::writer_loop, this);
}

TapDriver::~TapDriver() {
    m_running = false;
    m_cv.notify_all();
    if (m_writer_thread.joinable()) {
        m_writer_thread.join();
    }
    if (m_tap != INVALID_HANDLE_VALUE) {
        CloseHandle(m_tap);
    }
}

bool TapDriver::init(const char* device_guid) {
    char devicePath[256];
    sprintf_s(devicePath, sizeof(devicePath), TAP_WIN_PATH, device_guid);
    
    m_tap = CreateFileA(devicePath, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    
    if (m_tap == INVALID_HANDLE_VALUE) return false;

    ULONG status = TRUE; DWORD len;
    DeviceIoControl(m_tap, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL);
    return true;
}

void TapDriver::send_async(const uint8_t* buf, int len) {
    if (len <= 0 || len > 2000) return; // Basic sanity check, Ethernet MTU is usually 1500
    
    TrafficManager::instance().report_tap_rx(len);

    {
        std::lock_guard<std::mutex> lock(m_mtx);
        
        // Calculate free space
        size_t free_space = (m_read_idx - m_write_idx - 1 + m_size) % m_size;
        
        // Need space for: Length Header (4 bytes) + Data
        size_t needed = sizeof(int) + len;

        if (free_space < needed) {
            // Buffer Full: Drop packet to preserve latency (Backpressure)
            return; 
        }

        // A. Write Length Header
        int packet_len = len;
        if (m_write_idx + sizeof(int) <= m_size) {
            memcpy(&m_buffer[m_write_idx], &packet_len, sizeof(int));
        } else {
            size_t first = m_size - m_write_idx;
            memcpy(&m_buffer[m_write_idx], &packet_len, first);
            memcpy(&m_buffer[0], ((char*)&packet_len) + first, sizeof(int) - first);
        }
        m_write_idx = (m_write_idx + sizeof(int)) % m_size;

        // B. Write Packet Data
        if (m_write_idx + len <= m_size) {
            memcpy(&m_buffer[m_write_idx], buf, len);
        } else {
            size_t first = m_size - m_write_idx;
            memcpy(&m_buffer[m_write_idx], buf, first);
            memcpy(&m_buffer[0], buf + first, len - first);
        }
        m_write_idx = (m_write_idx + len) % m_size;
    }
    m_cv.notify_one();
}

void TapDriver::writer_loop() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    
    OVERLAPPED ol = {0};
    ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    if (!ol.hEvent) return;

    // Local buffer for writing to API
    uint8_t local_buf[2048]; 

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
                if (len > sizeof(local_buf)) len = sizeof(local_buf);

                // B. Read Data
                if (len > 0) {
                    if (m_read_idx + len <= m_size) {
                        memcpy(local_buf, &m_buffer[m_read_idx], len);
                    } else {
                        size_t first = m_size - m_read_idx;
                        memcpy(local_buf, &m_buffer[m_read_idx], first);
                        memcpy(local_buf + first, &m_buffer[0], len - first);
                    }
                    m_read_idx = (m_read_idx + len) % m_size;
                }
            }
        } // Unlock immediately to let Worker write more packets

        if (m_tap != INVALID_HANDLE_VALUE && len > 0) {
            DWORD written = 0;
            // Reset Overlapped
            ol.Internal = 0;
            ol.InternalHigh = 0;
            ol.Offset = 0;
            ol.OffsetHigh = 0;
            ResetEvent(ol.hEvent);

            if (!WriteFile(m_tap, local_buf, len, &written, &ol)) {
                if (GetLastError() == ERROR_IO_PENDING) {
                    WaitForSingleObject(ol.hEvent, 1000); 
                }
            }
        }
    }
    
    CloseHandle(ol.hEvent);
}