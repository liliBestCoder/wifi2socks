#ifndef TCB_H
#define TCB_H
#include <cstdint>
#include <vector>
#include "packet.h"


struct TCB {
	Quad quad;
	uint32_t seq, ack;
	std::vector<Packet> send_buf; 

	TCB(const Quad& q) : quad(q), seq(0), ack(0) {}


	void on_packet(const Packet& pkt);


	void flush_output();


	bool is_rto_expired(uint64_t now);
	void on_timeout();
};

inline void process_tcp_packet(TCB& t, const Packet& pkt) {
	t.on_packet(pkt);
}

inline void flush_output(TCB& t) {
	for (auto& p : t.send_buf) {
	}
	t.send_buf.clear();
}

#endif