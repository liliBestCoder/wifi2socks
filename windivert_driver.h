#pragma once

#include "windivert.h"
#include <string>
#include <functional>
#include <thread>
#include <vector>

class WinDivertDriver {
public:
    using PacketHandler = std::function<void(const char*, size_t, const WINDIVERT_ADDRESS*)>;

    WinDivertDriver(const std::string& filter);
    ~WinDivertDriver();

    bool start(PacketHandler handler);
    void stop();
    bool send(const char* packet, size_t length, const WINDIVERT_ADDRESS* addr);

private:
    void run();

    HANDLE handle_;
    std::string filter_;
    PacketHandler packet_handler_;
    std::thread worker_thread_;
    bool running_;
    std::vector<char> packet_buffer_;
};
