#include <cstdint>
#include <ws2tcpip.h>
#include <stdio.h>
#include <thread>
#include "utils.h"
#include "queue.h"

extern uint32_t GATEWAY_IP;
extern uint8_t TAP_MAC[6];



struct ArpEvent {
    uint8_t buffer[64];
    DWORD len;
};

#pragma pack(push, 1)
struct EthHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct ArpPacket {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
};
#pragma pack(pop)

struct ArpWorker {
	HANDLE tap;
    RingQueue<ArpEvent>* in_queue;
    std::thread th;
    std::atomic<bool> running{ false };

    ArpWorker(HANDLE tap, RingQueue<ArpEvent>* q);
    void run();
    void worker_loop();
    bool send_arp_reply(ArpEvent ev);
};