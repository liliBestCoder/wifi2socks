#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "tcb.h"
#include "tcb_utils.h"
#include "utils.h"
#include "arp.h"
#include <iostream>
#include <chrono>

// Helper: Construct and send a TCP packet
static void send_tcp(HANDLE tap, const Quad& q, uint32_t seq, uint32_t ack, uint8_t flags, const void* data, int len) {
    uint8_t frame[1514];
    // Ethernet
    memcpy(frame, TAP_MAC, 6);
    memcpy(frame + 6, TAP_MAC, 6); 
    *(uint16_t*)(frame + 12) = htons(0x0800);

    // IP
    uint8_t* ip = frame + 14;
    uint8_t* tcp = ip + 20;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    uint16_t tot_len = 20 + 20 + len;
    *(uint16_t*)(ip + 2) = htons(tot_len);
    ip[8] = 64; // TTL
    ip[9] = 6; // TCP
    // Quad is Network Order. IP Header expects Network Order. Copy directly.
    *(uint32_t*)(ip + 12) = q.daddr; // Src IP (Server)
    *(uint32_t*)(ip + 16) = q.saddr; // Dst IP (Client)
    *(uint16_t*)(ip + 10) = checksum(ip, 20);

    // TCP
    memset(tcp, 0, 20);
    // Quad is Network Order. TCP Header expects Network Order. Copy directly.
    *(uint16_t*)(tcp + 0) = q.dport; // Src Port
    *(uint16_t*)(tcp + 2) = q.sport; // Dst Port
    *(uint32_t*)(tcp + 4) = htonl(seq); // seq/ack are Host Order in TCB, need htonl
    *(uint32_t*)(tcp + 8) = htonl(ack);
    tcp[12] = 0x50; // Header len 20 bytes
    tcp[13] = flags;
    *(uint16_t*)(tcp + 14) = htons(64240); // Window

    if (len > 0) {
        memcpy(tcp + 20, data, len);
    }

    *(uint16_t*)(tcp + 16) = tcp_cksum(q.daddr, q.saddr, tcp, 20 + len);

    platform_send_frame(tap, frame, 14 + tot_len);
}

// Backend Thread: Connects to SOCKS5 and relays data
static void tcb_backend_loop(TCB* tcb) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return;

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(SOCKS_SERVER_IP);
    addr.sin_port = htons(SOCKS_SERVER_PORT);

    printf("[TCB] Connecting to SOCKS5 %s:%d...\n", SOCKS_SERVER_IP, SOCKS_SERVER_PORT);
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
        printf("[TCB] SOCKS5 connect failed: %d\n", WSAGetLastError());
        closesocket(s);
        return;
    }

    // SOCKS5 Handshake
    uint8_t handshake[] = { 0x05, 0x01, 0x00 };
    send(s, (char*)handshake, 3, 0);
    uint8_t buf[2048];
    int r = recv(s, (char*)buf, 2, 0);
    if (r != 2 || buf[1] != 0x00) {
        printf("[TCB] SOCKS5 handshake failed\n");
        closesocket(s);
        return;
    }

    // SOCKS5 Connect
    printf("[TCB] SOCKS5 Handshake OK. Requesting connection...\n");
    uint8_t req[10];
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01; // IPv4
    *(uint32_t*)(req + 4) = tcb->quad.daddr;
    *(uint16_t*)(req + 8) = tcb->quad.dport; // Quad is Net Order, Packet expects Net Order
    send(s, (char*)req, 10, 0);
    
    r = recv(s, (char*)buf, 10, 0);
    if (r < 10 || buf[1] != 0x00) {
        printf("[TCB] SOCKS5 connect request failed or rejected.\n");
        closesocket(s);
        return;
    }

    printf("[TCB] SOCKS5 Tunnel ESTABLISHED.\n");
    tcb->client_sock = s;

    // Relay Loop
    while (!tcb->stop_thread) {
        fd_set rd_set;
        FD_ZERO(&rd_set);
        FD_SET(s, &rd_set);

        timeval tv = { 0, 10000 }; // 10ms
        int n = select(0, &rd_set, NULL, NULL, &tv);

        if (n > 0) {
            r = recv(s, (char*)buf, sizeof(buf), 0);
            if (r <= 0) break;
            
            std::lock_guard<std::mutex> lk(tcb->mtx);
            for (int i = 0; i < r; ++i) tcb->data_to_tap.push_back(buf[i]);
        }

        // Send pending data
        {
            std::lock_guard<std::mutex> lk(tcb->mtx);
            while (!tcb->data_to_socks.empty()) {
                // Send in chunks
                std::vector<uint8_t> chunk;
                while (!tcb->data_to_socks.empty() && chunk.size() < 1400) {
                    chunk.push_back(tcb->data_to_socks.front());
                    tcb->data_to_socks.pop_front();
                }
                // printf("[TCB] Sending %zu bytes to SOCKS\n", chunk.size());
                send(s, (char*)chunk.data(), (int)chunk.size(), 0);
            }
        }
    }
    closesocket(s);
    tcb->client_sock = INVALID_SOCKET;
    tcb->state = TcpState::CLOSED; 
}

TCB::TCB(const Quad& q) : quad(q), state(TcpState::CLOSED), local_seq(0), local_ack(0), remote_seq(0), client_sock(INVALID_SOCKET), stop_thread(false) {
    local_seq = 0x12345678; 
}

TCB::~TCB() {
    stop_thread = true;
    if (backend_th.joinable()) backend_th.join();
}

void process_tcp_packet(TCB& tcb, const Packet& pkt, HANDLE tap) {
    TcpHdr* tcp = (TcpHdr*)pkt.payload.data();
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack_seq);
    int head_len = (tcp->data_offset >> 4) * 4;
    int pay_len = pkt.pay_len - head_len;
    if (pay_len < 0) pay_len = 0;
    uint8_t flags = tcp->flags;

    // Simple State Machine
    if (flags & 0x02) { // SYN
        if (tcb.state == TcpState::CLOSED || tcb.state == TcpState::SYN_RCVD) {
            printf("[TCB] Recv SYN. Sending SYN-ACK.\n");
            tcb.remote_seq = seq + 1;
            
            if (tcb.state == TcpState::CLOSED) {
                tcb.state = TcpState::SYN_RCVD;
                tcb.backend_th = std::thread(tcb_backend_loop, &tcb);
            }
            send_tcp(tap, tcb.quad, tcb.local_seq, tcb.remote_seq, 0x12, NULL, 0); // SYN|ACK
            if (tcb.state == TcpState::CLOSED) tcb.local_seq++; 
        }
    }
    else if (flags & 0x01) { // FIN
        printf("[TCB] Recv FIN.\n");
        tcb.remote_seq = seq + 1;
        tcb.state = TcpState::CLOSE_WAIT;
        send_tcp(tap, tcb.quad, tcb.local_seq, tcb.remote_seq, 0x10, NULL, 0); // ACK
        tcb.stop_thread = true;
    }
    else if (flags & 0x10) { // ACK
        if (tcb.state == TcpState::SYN_RCVD) {
            // Allow loose ACK check for now to be robust
            printf("[TCB] Recv ACK. State ESTABLISHED.\n");
            tcb.state = TcpState::ESTABLISHED;
        }
        
        if (tcb.state == TcpState::ESTABLISHED) {
            if (pay_len > 0) {
                // printf("[TCB] Recv Data %d bytes. Spooling to SOCKS.\n", pay_len);
                tcb.remote_seq = seq + pay_len;
                // Buffer data for SOCKS
                {
                    std::lock_guard<std::mutex> lk(tcb.mtx);
                    const uint8_t* data_ptr = pkt.payload.data() + head_len;
                    for(int i=0; i<pay_len; ++i) tcb.data_to_socks.push_back(data_ptr[i]);
                }
                // Send ACK immediately
                send_tcp(tap, tcb.quad, tcb.local_seq, tcb.remote_seq, 0x10, NULL, 0);
            }
        }
    }
    else if (flags & 0x04) { // RST
         printf("[TCB] Recv RST.\n");
         tcb.state = TcpState::CLOSED;
         tcb.stop_thread = true;
    }
}

void flush_output(TCB& tcb, HANDLE tap) {
    if (tcb.state == TcpState::ESTABLISHED) {
        std::lock_guard<std::mutex> lk(tcb.mtx);
        if (!tcb.data_to_tap.empty()) {
            std::vector<uint8_t> buf;
            while (!tcb.data_to_tap.empty() && buf.size() < 1400) {
                buf.push_back(tcb.data_to_tap.front());
                tcb.data_to_tap.pop_front();
            }
            // printf("[TCB] Flushing %zu bytes to TAP\n", buf.size());
            send_tcp(tap, tcb.quad, tcb.local_seq, tcb.remote_seq, 0x18, buf.data(), (int)buf.size()); // PSH|ACK
            tcb.local_seq += (uint32_t)buf.size();
        }
    }
}