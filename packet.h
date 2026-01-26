// ===== include/packet.h =====
#ifndef PACKET_H
#define PACKET_H

#include <cstdint>

struct Quad {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;

    bool operator==(const Quad& other) const {
        return saddr == other.saddr && daddr == other.daddr
            && sport == other.sport && dport == other.dport;
    }
};

namespace std {
    template<> struct hash<Quad> {
        size_t operator()(const Quad& q) const {
            return std::hash<uint32_t>()(q.saddr) ^ std::hash<uint32_t>()(q.daddr << 1)
                ^ std::hash<uint16_t>()(q.sport << 2) ^ std::hash<uint16_t>()(q.dport << 3);
        }
    };
}

struct Packet {
    Quad quad;
    std::vector<uint8_t> payload;
    int pay_len;
};

#endif