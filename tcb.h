#ifndef TCB_H
#define TCB_H
#include <cstdint>
#include <vector>
#include <thread>
#include <mutex>
#include <deque>
#include <atomic>
#include <ws2tcpip.h>
#include "packet.h"

enum class TcpState {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT
};

struct TCB {
    Quad quad;
    uint32_t local_seq; // Next sequence number to send (SEQ)
    uint32_t local_ack; // Next sequence number expected (ACK)
    uint32_t remote_seq; // Highest sequence number received
    
    TcpState state;
    
    // SOCKS5 & Backend
    SOCKET client_sock;
    std::thread backend_th;
    std::atomic<bool> stop_thread;
    
    // Buffers
    std::mutex mtx;
    std::deque<uint8_t> data_to_tap;   // Data received from SOCKS, waiting to be sent to TAP (TCP Payload)
    std::deque<uint8_t> data_to_socks; // Data received from TAP, waiting to be sent to SOCKS

    // Retransmission Support
    std::deque<uint8_t> unacked_data; // Data sent but not yet acknowledged
    uint32_t unacked_seq_start;       // SEQ of the first byte in unacked_data
    uint64_t last_send_time;          // Timestamp of last send (in milliseconds)

    // Retransmission & Window
    uint16_t window;
    
    TCB(const Quad& q);
    ~TCB();
};

#endif
