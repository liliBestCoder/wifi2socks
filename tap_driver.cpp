#include "tap_driver.h"
#include "app_config.h"
#include <cstdio>
#include <winioctl.h>

const uint8_t TapDriver::TAP_MAC[6] = { 0x00, 0xFF, 0x92, 0xEA, 0x69, 0x5C };

TapDriver& TapDriver::instance() {
    static TapDriver inst;
    return inst;
}

TapDriver::TapDriver() : m_tap(INVALID_HANDLE_VALUE), m_running(true) {
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
    if (len <= 0) return;
    
    // Optimization: Copy data and push to queue. Return immediately.
    // This unblocks the IOCP Worker thread.
    {
        std::lock_guard<std::mutex> lk(m_queue_mtx);
        if (m_write_queue.size() > 5000) {
            // Drop packet if queue is too full (Backpressure)
            // This prevents memory exhaustion if TAP is stuck
            return; 
        }
        m_write_queue.emplace_back(buf, buf + len);
    }
    m_cv.notify_one();
}

void TapDriver::writer_loop() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    
    OVERLAPPED ol = {0};
    ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    if (!ol.hEvent) return;

    while (m_running) {
        std::vector<uint8_t> packet;
        
        {
            std::unique_lock<std::mutex> lk(m_queue_mtx);
            m_cv.wait(lk, [this]() { return !m_write_queue.empty() || !m_running; });
            
            if (!m_running && m_write_queue.empty()) break;
            
            packet = std::move(m_write_queue.front());
            m_write_queue.pop_front();
        }
        
        if (m_tap != INVALID_HANDLE_VALUE && !packet.empty()) {
            DWORD written = 0;
            // Reset Overlapped
            ol.Internal = 0;
            ol.InternalHigh = 0;
            ol.Offset = 0;
            ol.OffsetHigh = 0;
            ResetEvent(ol.hEvent);

            if (!WriteFile(m_tap, packet.data(), (DWORD)packet.size(), &written, &ol)) {
                if (GetLastError() == ERROR_IO_PENDING) {
                    WaitForSingleObject(ol.hEvent, 1000); // Wait here is fine, this is the dedicated writer thread
                }
            }
        }
    }
    
    CloseHandle(ol.hEvent);
}
