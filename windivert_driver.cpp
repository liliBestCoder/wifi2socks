#include "windivert_driver.h"
#include "app_config.h"
#include "logger.h"

#pragma comment(lib, "WinDivert.lib")

WinDivertDriver::WinDivertDriver(const std::string& filter)
    : handle_(INVALID_HANDLE_VALUE), filter_(filter), running_(false), packet_buffer_(WINDIVERT_MTU_MAX), current_layer_(WINDIVERT_LAYER_NETWORK) {}

WinDivertDriver::~WinDivertDriver() {
    stop();
}

bool WinDivertDriver::start(PacketHandler handler) {
    packet_handler_ = handler;
    // 尝试使用 WINDIVERT_LAYER_ETHERNET 以支持二层拦截，绕过 ICS
    handle_ = WinDivertOpen(filter_.c_str(), WINDIVERT_LAYER_ETHERNET, 1000, 0);
    current_layer_ = WINDIVERT_LAYER_ETHERNET;

    if (handle_ == INVALID_HANDLE_VALUE && GetLastError() == 87) {
        LOG_INFO("WINDIVERT_LAYER_ETHERNET not supported (Driver version too old?). Falling back to WINDIVERT_LAYER_NETWORK...");
        handle_ = WinDivertOpen(filter_.c_str(), WINDIVERT_LAYER_NETWORK, 1000, 0);
        current_layer_ = WINDIVERT_LAYER_NETWORK;
    }

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
        read_len = 0;
        memset(&addr, 0, sizeof(addr));

        // 注意：根据最新的 windivert.h，Recv 的参数顺序是 (handle, packet, len, pRecvLen, pAddr)
        if (!WinDivertRecv(handle_, packet_buffer_.data(), (UINT)packet_buffer_.size(), &read_len, &addr)) {
            if (running_) {
                LOG_ERROR("WinDivertRecv failed with error: %d", GetLastError());
            }
            continue;
        }

        // 校验捕获长度，防止异常数据
        if (read_len == 0 || read_len > WINDIVERT_MTU_MAX) {
            LOG_ERROR("WinDivert captured invalid length: %u bytes.", read_len);
            continue;
        }

        if (packet_handler_) {
            packet_handler_(packet_buffer_.data(), (size_t)read_len, &addr);
        }
    }
}

bool WinDivertDriver::send(const char* packet, size_t length, const WINDIVERT_ADDRESS* addr) {
    if (handle_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    UINT write_len = 0;
    // 注意：根据最新的 windivert.h，Send 的参数顺序是 (handle, packet, len, pSendLen, pAddr)
    if (!WinDivertSend(handle_, (PVOID)packet, (UINT)length, &write_len, addr)) {
        LOG_ERROR("WinDivertSend failed with error: %d", GetLastError());
        return false;
    }
    return true;
}
