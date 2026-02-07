#include "windivert_driver.h"
#include "app_config.h"
#include "logger.h"

#pragma comment(lib, "WinDivert.lib")

WinDivertDriver::WinDivertDriver(const std::string& filter)
    : handle_(INVALID_HANDLE_VALUE), filter_(filter), running_(false), packet_buffer_(WINDIVERT_MTU) {}

WinDivertDriver::~WinDivertDriver() {
    stop();
}

bool WinDivertDriver::start(PacketHandler handler) {
    packet_handler_ = handler;
    // 提升优先级到 1000
    handle_ = WinDivertOpen(filter_.c_str(), WINDIVERT_LAYER_NETWORK, 1000, 0);
    if (handle_ == INVALID_HANDLE_VALUE) {
        LOG_INFO("Failed to open WinDivert handle. Error: %d. Make sure WinDivert.dll is in the same directory as the executable.", GetLastError());
        return false;
    }

    running_ = true;
    worker_thread_ = std::thread(&WinDivertDriver::run, this);
    LOG_INFO("WinDivert driver started with filter: %s", filter_.c_str());
    return true;
}

void WinDivertDriver::stop() {
    running_ = false;
    if (handle_ != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    LOG_INFO("WinDivert driver stopped.");
}

void WinDivertDriver::run() {
    WINDIVERT_ADDRESS addr;
    UINT read_len = 0;

    LOG_INFO("WinDivert capture loop entered.");

    while (running_) {
        if (!WinDivertRecv(handle_, packet_buffer_.data(), (UINT)packet_buffer_.size(), &addr, &read_len)) {
            if (running_) {
                LOG_ERROR("WinDivertRecv failed with error: %d", GetLastError());
            }
            continue;
        }

        // 每次抓到包都打印一条日志（调试用）
        LOG_INFO("WinDivert captured %u bytes", read_len);

        if (packet_handler_) {
            packet_handler_(packet_buffer_.data(), read_len, &addr);
        }
    }
}

bool WinDivertDriver::send(const char* packet, size_t length, const WINDIVERT_ADDRESS* addr) {
    if (handle_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    UINT write_len;
    if (!WinDivertSend(handle_, (PVOID)packet, (UINT)length, addr, &write_len)) {
        LOG_ERROR("WinDivertSend failed with error: %d", GetLastError());
        return false;
    }
    return true;
}
