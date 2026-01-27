#include "arp.h"
#include <thread>

uint32_t GATEWAY_IP = (10 << 24) | (0 << 16) | (0 << 8) | 1;   // 10.0.0.1 (host order)
uint8_t TAP_MAC[6] = { 0x00, 0xFF, 0x92, 0xEA, 0x69, 0x5C };

ArpWorker::ArpWorker(HANDLE tap, RingQueue<ArpEvent>* q) : tap(tap), in_queue(q) {}

void ArpWorker::worker_loop() {
    while (running.load()) {
        ArpEvent ev;
        while (in_queue->pop(ev)) {
            ArpWorker::send_arp_reply(ev);
        }
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
}

void ArpWorker::run() {
    running.store(true);
    th = std::thread([this] { worker_loop(); });
}

bool ArpWorker::send_arp_reply(ArpEvent ev) {
	dword len = ev.len;
	uint8_t* req = ev.buffer;
	HANDLE tap = this->tap;

    if (len < sizeof(EthHeader) + sizeof(ArpPacket))
        return false;

    EthHeader* eth = (EthHeader*)req;

    if (ntohs(eth->type) != 0x0806)   // ARP
        return false;

    ArpPacket* arp = (ArpPacket*)(req + sizeof(EthHeader));

    if (ntohs(arp->oper) != 1)        // ARP request
        return false;

    if (arp->tpa != htonl(GATEWAY_IP))
        return false;

    printf("[ARP-TAP] Request from ");
    print_mac(arp->sha);
    printf(" asking for gateway IP ");
    print_ip(arp->tpa);
    printf("\n");

    uint8_t reply[42] = { 0 };

    EthHeader* reth = (EthHeader*)reply;
    memcpy(reth->dst_mac, eth->src_mac, 6);
    memcpy(reth->src_mac, TAP_MAC, 6);
    reth->type = htons(0x0806);

    ArpPacket* rarp = (ArpPacket*)(reply + sizeof(EthHeader));
    rarp->htype = htons(1);
    rarp->ptype = htons(0x0800);
    rarp->hlen = 6;
    rarp->plen = 4;
    rarp->oper = htons(2); // ARP reply

    memcpy(rarp->sha, TAP_MAC, 6);
    rarp->spa = htonl(GATEWAY_IP);
    memcpy(rarp->tha, arp->sha, 6);
    rarp->tpa = arp->spa;

    DWORD written = 0;

    BOOL ok = WriteFile(tap, reply, sizeof(reply), &written, NULL);
    if (!ok) {
        //printf("[-] WriteFile ARP failed: %lu\n", GetLastError());
        return false;
    }

    printf("[ARP-TAP] Response with MAC ");
    print_mac(TAP_MAC);
    printf(" and IP ");
    print_ip(htonl(GATEWAY_IP));
    printf("\n");
    return true;
}