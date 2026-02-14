#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <vector>
#include <atomic>
#include <cstdint>
#include <memory>

#ifndef JUMBO_FRAME_SUPPORTED
#define JUMBO_FRAME_SUPPORTED 1
#endif

#include "Common.h"

// 使用 WinPkFilter 的中间缓冲区作为池对象类型
using RawPacket = INTERMEDIATE_BUFFER;

class PacketPool {
public:
    static PacketPool& instance();

    PacketPool(const PacketPool&) = delete;
    PacketPool& operator=(const PacketPool&) = delete;

    void init(size_t size = 8192);
    RawPacket* acquire();
    void release(RawPacket* p);

private:
    PacketPool() = default;
    ~PacketPool() = default;

    std::vector<RawPacket> m_storage;
    std::vector<RawPacket*> m_pool;
    std::atomic_flag m_lock = ATOMIC_FLAG_INIT;
};

struct PacketPoolDeleter {
    void operator()(RawPacket* p) const {
        PacketPool::instance().release(p);
    }
};

using RawPacketPtr = std::unique_ptr<RawPacket, PacketPoolDeleter>;
