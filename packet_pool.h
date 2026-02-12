#pragma once
#include <vector>
#include <mutex>
#include <cstdint>
#include <memory>

#ifndef JUMBO_FRAME_SUPPORTED
#define JUMBO_FRAME_SUPPORTED 1
#endif

#include "Common.h"

struct RawPacket {
    uint8_t data[MAX_ETHER_FRAME];
    uint32_t length;
};

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
    std::mutex m_mutex;
};

struct PacketPoolDeleter {
    void operator()(RawPacket* p) const {
        PacketPool::instance().release(p);
    }
};

using RawPacketPtr = std::unique_ptr<RawPacket, PacketPoolDeleter>;
