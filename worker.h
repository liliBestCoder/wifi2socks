// ===== include/worker.h =====
#ifndef WORKER_H
#define WORKER_H
#include <ws2tcpip.h>
#include <thread>
#include <unordered_map>
#include <memory>
#include "tcb.h"
#include "ucb.h"
#include "queue.h"
#include "packet.h"

enum class EventType { PacketIn, TimerRTO };

struct Event {
	EventType type;
	Packet pkt; // PacketIn
	Quad quad; // TimerRTO
	UINT8 proto;
};

struct Worker {
	int id;
	HANDLE tap;
	RingQueue<Event>* in_queue;
	std::thread th;
	std::unordered_map<Quad, std::unique_ptr<TCB>> tcb_map;
	std::unordered_map<Quad, std::unique_ptr<UCB>> ucb_map;
	std::atomic<bool> running{ false };


	Worker(int i, HANDLE tap, RingQueue<Event>* q);
	void run();
	void worker_loop();
	void process_event(const Event& ev);
};

struct IpHdr {
	BYTE ver_ihl;
	BYTE tos;
	WORD tot_len;
	WORD id;
	WORD frag_off;
	BYTE ttl;
	BYTE protocol;
	WORD checksum;
	DWORD src;
	DWORD dst;
};

struct TcpHdr {
	WORD src_port;
	WORD dst_port;
	DWORD seq;
	DWORD ack_seq;
	BYTE data_offset;
	BYTE flags;
	WORD window;
	WORD checksum;
	WORD urgent;
};

void init_workers(HANDLE tap);

void dispatch(uint8_t* buffer, DWORD bytesRead);
#endif