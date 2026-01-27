#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "tcb.h"
#include "tcb_utils.h"
#include "utils.h"
#include "arp.h"
#include <iostream>
#include <chrono>

// Helper: Get current time in ms
static uint64_t get_now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// Helper: Construct and send a TCP packet
// mss: if > 0, adds MSS option
static void send_tcp(HANDLE tap, const Quad& q, uint32_t seq, uint32_t ack, uint8_t flags, const void* data, int len, uint16_t mss = 0) {
    uint8_t frame[1514];
    
    // Calculate Option Length
    int opt_len = (mss > 0) ? 4 : 0;
    int tcp_header_len = 20 + opt_len;
    // Pad header to 4-byte boundary if needed (MSS option is 4 bytes, so usually aligned) 
    
    // Ethernet
    memcpy(frame, TAP_MAC, 6);
    memcpy(frame + 6, TAP_MAC, 6); 
    *(uint16_t*)(frame + 12) = htons(0x0800);

    // IP
    uint8_t* ip = frame + 14;
    uint8_t* tcp = ip + 20;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    uint16_t tot_len = 20 + tcp_header_len + len;
    *(uint16_t*)(ip + 2) = htons(tot_len);
    ip[8] = 64; // TTL
    ip[9] = 6; // TCP
    *(uint32_t*)(ip + 12) = q.daddr; 
    *(uint32_t*)(ip + 16) = q.saddr; 
    *(uint16_t*)(ip + 10) = checksum(ip, 20);

    // TCP
    memset(tcp, 0, 20 + opt_len); // Clear header + options
    *(uint16_t*)(tcp + 0) = q.dport; 
    *(uint16_t*)(tcp + 2) = q.sport; 
    *(uint32_t*)(tcp + 4) = htonl(seq); 
    *(uint32_t*)(tcp + 8) = htonl(ack);
    
    // Data Offset: header len / 4. 
    // If len is 20, 20/4 = 5 (0x50). If 24, 24/4 = 6 (0x60).
    uint8_t offset_val = (tcp_header_len / 4) << 4;
    tcp[12] = offset_val; 
    
    tcp[13] = flags;
    *(uint16_t*)(tcp + 14) = htons(64240); 

    // TCP Options
    if (mss > 0) {
        tcp[20] = 0x02; // Kind: MSS
        tcp[21] = 0x04; // Len: 4
        *(uint16_t*)(tcp + 22) = htons(mss);
    }

    // Payload
    if (len > 0) {
        memcpy(tcp + tcp_header_len, data, len);
    }

    *(uint16_t*)(tcp + 16) = tcp_cksum(q.daddr, q.saddr, tcp, tcp_header_len + len);

    platform_send_frame(tap, frame, 14 + tot_len);
}

// Helper to read N bytes strictly
static bool recv_all(SOCKET s, uint8_t* buf, int len) {
    int total = 0;
    while (total < len) {
        int r = recv(s, (char*)buf + total, len - total, 0);
        if (r <= 0) return false;
        total += r;
    }
    return true;
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

    // SOCKS5 Handshake (Auth Negotiation)
    uint8_t handshake[] = { 0x05, 0x01, 0x00 };
    send(s, (char*)handshake, 3, 0);
    uint8_t buf[2048];
    
    // Read 2 bytes (VER, METHOD)
    if (!recv_all(s, buf, 2)) {
        printf("[TCB] SOCKS5 handshake recv failed\n");
        closesocket(s);
        return;
    }
    if (buf[1] != 0x00) {
        printf("[TCB] SOCKS5 auth failed (method=%02x)\n", buf[1]);
        closesocket(s);
        return;
    }

    // SOCKS5 Connect Request
    printf("[TCB] SOCKS5 Handshake OK. Requesting connection...\n");
    uint8_t req[10];
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01; // IPv4
    *(uint32_t*)(req + 4) = tcb->quad.daddr;
    *(uint16_t*)(req + 8) = tcb->quad.dport; 
    send(s, (char*)req, 10, 0);
    
    // SOCKS5 Connect Reply Parsing (Robust)
    // 1. Read header (4 bytes): VER, REP, RSV, ATYP
    if (!recv_all(s, buf, 4)) {
        printf("[TCB] SOCKS5 reply header recv failed\n");
        closesocket(s);
        return;
    }

    if (buf[1] != 0x00) {
        printf("[TCB] SOCKS5 connect rejected (rep=%02x)\n", buf[1]);
        closesocket(s);
        return;
    }

    uint8_t atyp = buf[3];
    int addr_to_read = 0;
    
    if (atyp == 0x01) { // IPv4
        addr_to_read = 4;
    } else if (atyp == 0x04) { // IPv6
        addr_to_read = 16;
    } else if (atyp == 0x03) { // Domain
        // Read 1 byte length
        if (!recv_all(s, buf, 1)) {
            closesocket(s); return;
        }
        addr_to_read = buf[0]; // Domain length
    } else {
        printf("[TCB] Unknown ATYP %02x\n", atyp);
        closesocket(s);
        return;
    }

    // Read Address
    if (addr_to_read > 0) {
        if (!recv_all(s, buf, addr_to_read)) {
            closesocket(s); return;
        }
    }

    // Read Port (2 bytes)
    if (!recv_all(s, buf, 2)) {
        closesocket(s); return;
    }

    printf("[TCB] SOCKS5 Tunnel ESTABLISHED. Ready for data.\n");
    tcb->client_sock = s;

    // Relay Loop
    while (true) {
        // Check exit condition BUT continue if we have data to write
        bool should_stop = tcb->stop_thread;
        bool has_data_to_send;
        {
            std::lock_guard<std::mutex> lk(tcb->mtx);
            has_data_to_send = !tcb->data_to_socks.empty();
        }

        if (should_stop && !has_data_to_send) {
            break;
        }

        fd_set rd_set;
        FD_ZERO(&rd_set);
        FD_SET(s, &rd_set);

        timeval tv = { 0, 10000 }; // 10ms
        int n = select(0, &rd_set, NULL, NULL, &tv);

        if (n > 0) {
            int r = recv(s, (char*)buf, sizeof(buf), 0);
            if (r <= 0) break;
            
            std::lock_guard<std::mutex> lk(tcb->mtx);
            for (int i = 0; i < r; ++i) tcb->data_to_tap.push_back(buf[i]);
        }

        // Send pending data to SOCKS (Flush even if stopping)
        {
            std::lock_guard<std::mutex> lk(tcb->mtx);
            while (!tcb->data_to_socks.empty()) {
                std::vector<uint8_t> chunk;
                while (!tcb->data_to_socks.empty() && chunk.size() < 1400) {
                    chunk.push_back(tcb->data_to_socks.front());
                    tcb->data_to_socks.pop_front();
                }
                send(s, (char*)chunk.data(), (int)chunk.size(), 0);
            }
        }
    }
    closesocket(s);
    tcb->client_sock = INVALID_SOCKET;
    tcb->state = TcpState::CLOSED; 
}

TCB::TCB(const Quad& q) : quad(q), state(TcpState::CLOSED), local_seq(0), local_ack(0), remote_seq(0), client_sock(INVALID_SOCKET), stop_thread(false), last_send_time(0) {
    local_seq = 0x12345678; 
}

TCB::~TCB() {
    stop_thread = true;
    if (backend_th.joinable()) backend_th.join();
}

void process_tcp_packet(TCB& tcb, const Packet& pkt, HANDLE tap) {
    if (pkt.payload.size() < 20) return; // Drop too short packets
    TcpHdr* tcp = (TcpHdr*)pkt.payload.data();
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack_seq);
    
    // Correctly calculate head length: Data Offset is high 4 bits
    int head_len = (tcp->data_offset >> 4) * 4;
    int pay_len = pkt.pay_len - head_len;
    if (pay_len < 0) pay_len = 0;
    
    uint8_t flags = tcp->flags;

    // RST: Reset connection
    if (flags & 0x04) { 
         printf("[TCB] Recv RST. Closing TCB.\n");
         tcb.state = TcpState::CLOSED;
         tcb.stop_thread = true;
         return;
    }

    // SYN: Establish connection
    if (flags & 0x02) { 
        if (tcb.state == TcpState::CLOSED || tcb.state == TcpState::SYN_RCVD) {
            printf("[TCB] Recv SYN. Sending SYN-ACK. (seq=%u)\n", seq);
            tcb.remote_seq = seq + 1;
            
            if (tcb.state == TcpState::CLOSED) {
                tcb.state = TcpState::SYN_RCVD;
                tcb.backend_th = std::thread(tcb_backend_loop, &tcb);
            }
            
            // Retransmission Logic: Use original local_seq if retransmitting
            uint32_t syn_ack_seq = (tcb.state == TcpState::SYN_RCVD) ? tcb.local_seq - 1 : tcb.local_seq;
            
            // Send MSS option 1360 to avoid fragmentation
            send_tcp(tap, tcb.quad, syn_ack_seq, tcb.remote_seq, 0x12, NULL, 0, 1360); 
            
            if (tcb.state == TcpState::CLOSED) tcb.local_seq++; 
        }
        return; 
    }

    // ACK Processing
    if (flags & 0x10) { 
        if (tcb.state == TcpState::SYN_RCVD) {
            if (ack == tcb.local_seq) {
                printf("[TCB] Recv ACK (Handshake). State ESTABLISHED.\n");
                tcb.state = TcpState::ESTABLISHED;
            }
        }
        
        if (tcb.state == TcpState::ESTABLISHED) {
            // Check if this ACK confirms any of our sent data
            // unacked_data stores the LAST N bytes sent.
            // So seq of first byte in unacked_data is: local_seq - unacked_data.size()
            
            std::lock_guard<std::mutex> lk(tcb.mtx);
            uint32_t unacked_start_seq = tcb.local_seq - (uint32_t)tcb.unacked_data.size();
            
            // Ack is what client expects NEXT. So acknowledged bytes = ack - unacked_start_seq.
            if (!tcb.unacked_data.empty()) {
                int acked_bytes = ack - unacked_start_seq;
                if (acked_bytes > 0 && acked_bytes <= (int)tcb.unacked_data.size()) {
                    // Remove confirmed bytes
                    // printf("[TCB] Client ACKed %d bytes.\n", acked_bytes);
                    for(int i=0; i<acked_bytes; ++i) tcb.unacked_data.pop_front();
                }
            }

            // Receive New Data
            if (pay_len > 0) {
                printf("[TCB] Recv Data %d bytes. Spooling to SOCKS.\n", pay_len);
                tcb.remote_seq = seq + pay_len;
                const uint8_t* data_ptr = pkt.payload.data() + head_len;
                for(int i=0; i<pay_len; ++i) tcb.data_to_socks.push_back(data_ptr[i]);
                
                // Send ACK immediately to keep flow going
                send_tcp(tap, tcb.quad, tcb.local_seq, tcb.remote_seq, 0x10, NULL, 0);
            }
        }
    }

    // FIN: Close connection
    if (flags & 0x01) { 
        printf("[TCB] Recv FIN. (seq=%u)\n", seq);
        tcb.remote_seq = seq + pay_len + 1; 
        tcb.state = TcpState::CLOSE_WAIT;
        send_tcp(tap, tcb.quad, tcb.local_seq, tcb.remote_seq, 0x10, NULL, 0); // ACK the FIN
        tcb.stop_thread = true;
    }
}

void flush_output(TCB& tcb, HANDLE tap) {
    if (tcb.state == TcpState::ESTABLISHED) {
        uint64_t now = get_now_ms();
        std::lock_guard<std::mutex> lk(tcb.mtx);

        // 1. Send New Data
        if (!tcb.data_to_tap.empty()) {
            std::vector<uint8_t> buf;
            while (!tcb.data_to_tap.empty() && buf.size() < 1360) {
                buf.push_back(tcb.data_to_tap.front());
                tcb.data_to_tap.pop_front();
            }
            
            // Store for retransmission
            for(uint8_t b : buf) tcb.unacked_data.push_back(b);
            
            // Send
            printf("[TCB] Sending %zu bytes to TAP. Seq=%u\n", buf.size(), tcb.local_seq);
            send_tcp(tap, tcb.quad, tcb.local_seq, tcb.remote_seq, 0x18, buf.data(), (int)buf.size()); // PSH|ACK
            
            tcb.local_seq += (uint32_t)buf.size();
            tcb.last_send_time = now;
        }
        
        // 2. Retransmission Check (Independent check)
        else if (!tcb.unacked_data.empty()) {
            if (now - tcb.last_send_time > 300) { // 300ms RTO
                printf("[TCB] *** RTO! Retransmitting %zu bytes. ***\n", tcb.unacked_data.size());
                
                // Calculate SEQ for retransmission
                uint32_t seq = tcb.local_seq - (uint32_t)tcb.unacked_data.size();
                
                // Convert deque to vector
                std::vector<uint8_t> buf(tcb.unacked_data.begin(), tcb.unacked_data.end());
                
                // Limit retransmission size (MTU safe)
                if (buf.size() > 1360) buf.resize(1360);

                send_tcp(tap, tcb.quad, seq, tcb.remote_seq, 0x18, buf.data(), (int)buf.size());
                
                tcb.last_send_time = now; // Reset timer
            }
        }
    }
}
