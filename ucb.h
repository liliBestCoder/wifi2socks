#ifndef UCB_H
#define UCB_H
#include <ws2tcpip.h>
#include <cstdint>
#include <vector>
#include "packet.h"

struct UCB {
	Quad quad;
    SOCKET udpSock; 
	std::vector<Packet> send_buf;
    //uint8_t  cli_mac[6]; // 客户端 MAC，回包时要用
	UCB(const Quad& q) : quad(q), udpSock(INVALID_SOCKET) {}

	void on_packet(const Packet& pkt, HANDLE tap);

	void flush_output();
};

inline void process_tcp_packet(UCB& t, const Packet& pkt, HANDLE tap) {
	t.on_packet(pkt, tap);
}

inline void flush_output(UCB& t) {
	t.flush_output();
}
#endif
