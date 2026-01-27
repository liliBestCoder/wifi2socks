// ===== include/packet.h =====
#ifndef PACKET_H
#define PACKET_H

#include <cstdint>
#include <vector>

#pragma pack(push, 1)
struct EthHeader {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
};

struct IpHdr {
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src;
	uint32_t dst;
};

struct TcpHdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack_seq;
	uint8_t data_offset;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent;
};

struct UdpHdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t checksum;
};
#pragma pack(pop)

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