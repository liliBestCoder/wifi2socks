#include "packet_monitor.h"
#include "logger.h"
#include <chrono>

PacketMonitor& PacketMonitor::instance() {
    static PacketMonitor monitor;
    return monitor;
}

PacketMonitor::PacketMonitor() : m_running(false) {}

PacketMonitor::~PacketMonitor() {
    stop();
}

void PacketMonitor::start(const std::string& pipe_name) {
    if (m_running) return;
    m_pipe_name = pipe_name;
    m_running = true;
    m_listen_thread = std::thread(&PacketMonitor::listen_thread, this);
    LOG_INFO("[Monitor] Wireshark pipeline started at %s", m_pipe_name.c_str());
}

void PacketMonitor::stop() {
    m_running = false;
    
    // Create a dummy connection to unblock ConnectNamedPipe if it's waiting
    HANDLE hPipe = CreateFileA(m_pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);

    if (m_listen_thread.joinable()) m_listen_thread.join();

    std::lock_guard<std::mutex> lock(m_mutex);
    for (HANDLE h : m_clients) {
        DisconnectNamedPipe(h);
        CloseHandle(h);
    }
    m_clients.clear();
}

void PacketMonitor::publish(const char* data, size_t len) {
    if (!m_running) return;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_clients.empty()) return;

    pcaprec_hdr_s rec_hdr;
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    rec_hdr.ts_sec = (uint32_t)std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    rec_hdr.ts_usec = (uint32_t)(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() % 1000000);
    rec_hdr.incl_len = (uint32_t)len;
    rec_hdr.orig_len = (uint32_t)len;

    std::vector<HANDLE> inactive_clients;
    for (HANDLE h : m_clients) {
        DWORD written;
        bool success = WriteFile(h, &rec_hdr, sizeof(rec_hdr), &written, NULL);
        if (success) {
            success = WriteFile(h, data, (DWORD)len, &written, NULL);
        }

        if (!success) {
            inactive_clients.push_back(h);
        }
    }

    // Cleanup disconnected clients
    for (HANDLE h : inactive_clients) {
        auto it = std::find(m_clients.begin(), m_clients.end(), h);
        if (it != m_clients.end()) {
            DisconnectNamedPipe(h);
            CloseHandle(h);
            m_clients.erase(it);
            LOG_INFO("[Monitor] Wireshark client disconnected.");
        }
    }
}

void PacketMonitor::listen_thread() {
    while (m_running) {
        HANDLE hPipe = CreateNamedPipeA(
            m_pipe_name.c_str(),
            PIPE_ACCESS_OUTBOUND,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536, 65536, 0, NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            if (!m_running) {
                CloseHandle(hPipe);
                break;
            }
            broadcast_header(hPipe);
            std::lock_guard<std::mutex> lock(m_mutex);
            m_clients.push_back(hPipe);
            LOG_INFO("[Monitor] Wireshark client connected.");
        } else {
            CloseHandle(hPipe);
        }
    }
}

void PacketMonitor::broadcast_header(HANDLE hPipe) {
    pcap_hdr_s hdr;
    hdr.magic_number = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = 65535;
    hdr.network = 1; // Ethernet

    DWORD written;
    WriteFile(hPipe, &hdr, sizeof(hdr), &written, NULL);
}
