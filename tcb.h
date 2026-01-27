#ifndef TCB_H
#define TCB_H
#include <winsock2.h>
#include <mswsock.h>
#include <cstdint>
#include <vector>
#include <deque>
#include <mutex>
#include "packet.h"

// IOCP Operation Types
enum class IO_OP {
    OP_CONNECT,
    OP_SOCKS_HANDSHAKE_SEND,
    OP_SOCKS_HANDSHAKE_RECV,
    OP_SOCKS_REQUEST_SEND,
    OP_SOCKS_REQUEST_RECV,
    OP_RELAY_RECV, // Receive from SOCKS
    OP_RELAY_SEND  // Send to SOCKS
};

// Extended Overlapped Structure
struct IO_CONTEXT {
    WSAOVERLAPPED overlapped;
    IO_OP op;
    WSABUF wsaBuf;
    char buffer[4096]; // Buffer for I/O operations
    
    void Reset(IO_OP operation) {
        memset(&overlapped, 0, sizeof(overlapped));
        op = operation;
        wsaBuf.buf = buffer;
        wsaBuf.len = sizeof(buffer);
    }
};

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
    uint32_t local_seq; 
    uint32_t local_ack; 
    uint32_t remote_seq; 
    
    TcpState state;
    
    // IOCP & Socket
    SOCKET client_sock;
    IO_CONTEXT recv_ctx; // Context for receiving from SOCKS
    IO_CONTEXT send_ctx; // Context for sending to SOCKS
    bool is_sending;     // Atomic-like flag to serialize sends
    
    // Buffers
    std::mutex mtx;
    std::deque<uint8_t> data_to_tap;   // Data received from SOCKS, waiting to be sent to TAP
    std::deque<uint8_t> data_to_socks; // Data received from TAP, waiting to be sent to SOCKS

    // Retransmission Support
    std::deque<uint8_t> unacked_data; 
    uint32_t unacked_seq_start;       
    uint64_t last_send_time;          

    uint16_t window;
    
    TCB(const Quad& q);
    ~TCB();

    // IOCP Methods
    void InitIOCP();
    void OnConnectCompleted(BOOL success);
    void OnRecvCompleted(DWORD bytesTransferred);
    void OnSendCompleted(DWORD bytesTransferred);
    void StartSocksHandshake();
    void StartSocksRequest();
    void StartRelay();
    void DoSend(); // Trigger WSASend if data exists
};

// Global IOCP Handle
extern HANDLE g_hIOCP;
void InitIOCPSystem();

#endif
