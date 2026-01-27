#include "worker.h"
#include <iostream>
#include "arp.h"

int NUM_WORKERS = 4;

Worker::Worker(int i, HANDLE tap, RingQueue<Event>* q) : id(i), tap(tap), in_queue(q) {}

void Worker::run() {
	running.store(true);
	th = std::thread([this] { worker_loop(); });
}

void Worker::worker_loop() {
	while (running.load()) {
		Event ev;
		while (in_queue->pop(ev)) {
			process_event(ev);
		}
		
		// Poll for outgoing data
		for (auto& kv : tcb_map) {
			flush_output(*kv.second, tap);
		}

		std::this_thread::sleep_for(std::chrono::microseconds(50)); 
	}
}

void Worker::process_event(const Event& ev) {
	if (ev.type == EventType::PacketIn) {
		if (ev.proto == IPPROTO_TCP) {
			auto it = tcb_map.find(ev.pkt.quad);
			if (it == tcb_map.end()) {
				tcb_map[ev.pkt.quad] = std::make_unique<TCB>(ev.pkt.quad);
			}
			TCB* t = tcb_map[ev.pkt.quad].get();
			process_tcp_packet(*t, ev.pkt, this->tap);
			flush_output(*t, this->tap);
		}
		else if (ev.proto == IPPROTO_UDP) {
			auto it = ucb_map.find(ev.pkt.quad);
			if (it == ucb_map.end()) {
				ucb_map[ev.pkt.quad] = std::make_unique<UCB>(ev.pkt.quad);
			}
			UCB* t = ucb_map[ev.pkt.quad].get();
			process_udp_packet(*t, ev.pkt, this->tap);
		}
	}
	else if (ev.type == EventType::TimerRTO) {
		auto it = tcb_map.find(ev.quad);
		if (it != tcb_map.end()) {
			// TCB* t = it->second.get();
			// Retransmission logic not implemented in simplified TCB
            // if (!t->send_buf.empty()) {
            //    std::cout << "[worker" << id << "] RTO triggered for "
            //        << t->quad.saddr << ":" << t->quad.sport << "\n";
            //    flush_output(*t, this->tap); // 重发
            // }
		}
	}
}

std::vector<std::unique_ptr<RingQueue<Event>>> queues;
std::vector<std::unique_ptr<Worker>> workers;
std::unique_ptr<RingQueue<ArpEvent>> arp_queue = std::make_unique<RingQueue<ArpEvent>>(1024);
std::unique_ptr<ArpWorker> arp_worker;

void init_workers(HANDLE tap) {
	for (int i = 0; i < NUM_WORKERS; ++i) {
		queues.push_back(std::make_unique<RingQueue<Event>>(1024));
		workers.push_back(std::make_unique<Worker>(i, tap, queues[i].get()));
		workers[i]->run();
	}
	arp_worker = std::make_unique<ArpWorker>(tap, arp_queue.get());
	arp_worker->run();
}

void dispatch_ip_packet(uint32_t saddr, uint32_t daddr,
	uint16_t sport, uint16_t dport,
	uint8_t proto,
	const std::vector<uint8_t>& payload,
	int pay_len,
	const std::vector<std::unique_ptr<RingQueue<Event>>>& queues) {

	// 1️⃣ 构造 Packet
	Packet pkt;
	pkt.quad = { saddr, daddr, sport, dport };
	pkt.payload = payload;
	pkt.pay_len = pay_len;

	// 2️⃣ 计算 hash，选择 Worker
	size_t hash = std::hash<Quad>()(pkt.quad);
	size_t worker_index = hash % queues.size();

	// 3️⃣ 构造事件
	Event ev;
	ev.type = EventType::PacketIn;
	ev.pkt = pkt;
	ev.proto = proto;

	// 4️⃣ 推送到队列
	while (!queues[worker_index]->push(ev)) {
		std::this_thread::sleep_for(std::chrono::microseconds(10)); // 队列满重试
	}
}

void dispatch(uint8_t* buffer, DWORD bytesRead) {
	EthHeader* eth = (EthHeader*)buffer;
	switch (ntohs(eth->type)) {
	case 0x0800: { // IPv4
		IpHdr* ip = (IpHdr*)(buffer + sizeof(EthHeader));
		uint8_t* payload = (uint8_t*)ip + (ip->ver_ihl & 0x0F) * 4;
		int payload_len = ntohs(ip->tot_len) - (ip->ver_ihl & 0x0F) * 4;
		if (payload_len < 0) payload_len = 0;

		std::vector<uint8_t> vec(payload, payload + payload_len);

		if (ip->protocol == 6) { // TCP
			TcpHdr* tcp = (TcpHdr*)payload;
			// FIXED: Pass the full TCP segment (Header + Data) so process_tcp_packet can read flags/seq
			std::vector<uint8_t> tcp_vec(payload, payload + payload_len);

			dispatch_ip_packet(ip->src, ip->dst, tcp->src_port, tcp->dst_port, IPPROTO_TCP, tcp_vec, payload_len, queues);
		}
		else if (ip->protocol == 17) { // UDP
			UdpHdr* udp = (UdpHdr*)payload;
			uint16_t sport = udp->src_port;
			uint16_t dport = udp->dst_port;

			/* 本地服务/组播/广播 直接丢弃 */
			if (ntohs(sport) == 137 || ntohs(sport) == 138 || ntohs(sport) == 5353 || ntohs(sport) == 5355 ||
				ntohs(dport) == 137 || ntohs(dport) == 138 || ntohs(dport) == 5353 || ntohs(dport) == 5355 ||
				(ip->dst & 0xF0000000) == 0xE0000000 ||   // 224.0.0.0/4
				(ip->dst & 0xFF) == 0xFF)                 // 广播
				return;
			
			int udp_payload_len = payload_len - sizeof(UdpHdr);
			if (udp_payload_len < 0) udp_payload_len = 0;
			std::vector<uint8_t> udp_vec(payload + sizeof(UdpHdr), payload + sizeof(UdpHdr) + udp_payload_len);
			dispatch_ip_packet(ip->src, ip->dst, sport, dport, IPPROTO_UDP, udp_vec, udp_payload_len, queues);
		}
		break;
	}
	case 0x0806: // ARP
		ArpEvent ev;
		memcpy(ev.buffer, buffer, bytesRead);
		ev.len = bytesRead;
		while (!arp_queue->push(ev)) {
			std::this_thread::sleep_for(std::chrono::microseconds(10));
		}
		break;
	default:
		break;
	}
}

