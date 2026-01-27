#ifndef UCB_H
#define UCB_H
#include <ws2tcpip.h>
#include <cstdint>
#include <vector>
#include <deque>
#include <thread>
#include <mutex>
#include <atomic>
#include "packet.h"

struct UCB {
    Quad quad;
    
    // SOCKS5 Control
    SOCKET tcpSock; // Keep-alive TCP connection for UDP Associate
    SOCKET udpSock; // UDP socket for data transfer
    
    // Relay Target (Where we send UDP packets to)
    uint32_t relay_ip;
    uint16_t relay_port;

    // Threading
    std::thread worker_th;
    std::atomic<bool> stop_thread;
    std::atomic<bool> ready_to_send;

    // Data Queue (Packets waiting for handshake to complete)
    std::mutex mtx;
    std::deque<Packet> send_queue; 

    UCB(const Quad& q);
    ~UCB();
};

#endif