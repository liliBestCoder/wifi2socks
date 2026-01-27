#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "tcb.h"
#include "tcb_utils.h"
#include "utils.h"
#include "arp.h"
#include <iostream>
#include <chrono>
#include <process.h> // for _beginthreadex

#pragma comment(lib, "Mswsock.lib") // For ConnectEx

HANDLE g_hIOCP = NULL;
LPFN_CONNECTEX g_pConnectEx = NULL;

// Helper: Get current time in ms
static uint64_t get_now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

static void LoadConnectEx() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return;
    
    GUID guid = WSAID_CONNECTEX;
    DWORD bytes = 0;
    WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid),
             &g_pConnectEx, sizeof(g_pConnectEx), &bytes, NULL, NULL);
    
    closesocket(s);
}

// IOCP Worker Thread
unsigned __stdcall IOCPWorkerThread(void* pParam) {
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED pOverlapped;

    while (true) {
        BOOL ret = GetQueuedCompletionStatus(g_hIOCP, &bytesTransferred, &completionKey, &pOverlapped, INFINITE);
        
        if (!ret && pOverlapped == NULL) {
            // Error not related to an I/O operation
            printf("[IOCP] GQCS Failed error=%d\n", GetLastError());
            continue; 
        }

        TCB* tcb = (TCB*)completionKey;
        IO_CONTEXT* ctx = (IO_CONTEXT*)pOverlapped;

        if (!tcb || !ctx) continue;

        // Check for error/closure
        if (!ret || (bytesTransferred == 0 && ctx->op != IO_OP::OP_CONNECT)) {
            // Connection closed or error
            // printf("[IOCP] Connection closed or error. OP=%d\n", (int)ctx->op);
            // Cleanup handled by TCB destructor usually, but here we just mark closed
            // Ideally we should close socket and stop processing.
            // For now, simple logic:
            continue; 
        }

        // Dispatch based on OP
        switch (ctx->op) {
            case IO_OP::OP_CONNECT:
                tcb->OnConnectCompleted(TRUE); // ConnectEx returns TRUE means "IO Pending" -> Completed. 
                break;
            case IO_OP::OP_SOCKS_HANDSHAKE_SEND:
                // Send done, now Read reply
                ctx->Reset(IO_OP::OP_SOCKS_HANDSHAKE_RECV);
                ctx->wsaBuf.len = 2; // Read 2 bytes (VER, METHOD)
                {
                    DWORD flags = 0;
                    WSARecv(tcb->client_sock, &ctx->wsaBuf, 1, NULL, &flags, &ctx->overlapped, NULL);
                }
                break;
            case IO_OP::OP_SOCKS_HANDSHAKE_RECV:
                // Check Auth
                if (bytesTransferred == 2 && ctx->buffer[1] == 0x00) {
                    tcb->StartSocksRequest();
                } else {
                    printf("[IOCP] Handshake failed\n");
                }
                break;
            case IO_OP::OP_SOCKS_REQUEST_SEND:
                // Send Request done, Read Reply header
                ctx->Reset(IO_OP::OP_SOCKS_REQUEST_RECV);
                ctx->wsaBuf.len = 10; // Simple assume 10 bytes IPv4 reply first, fix logic later for robustness if needed
                // Note: To support Variable length properly in IOCP is harder (need state machine inside Read).
                // For "One Step" fast implementation, we assume Proxy returns IPv4 (most do for Connect).
                {
                    DWORD flags = 0;
                    WSARecv(tcb->client_sock, &ctx->wsaBuf, 1, NULL, &flags, &ctx->overlapped, NULL);
                }
                break;
            case IO_OP::OP_SOCKS_REQUEST_RECV:
                // Check Reply
                if (bytesTransferred >= 10 && ctx->buffer[1] == 0x00) {
                    // Tunnel Est
                    tcb->StartRelay();
                } else {
                    printf("[IOCP] Request failed\n");
                }
                break;
            case IO_OP::OP_RELAY_RECV:
                tcb->OnRecvCompleted(bytesTransferred);
                break;
            case IO_OP::OP_RELAY_SEND:
                tcb->OnSendCompleted(bytesTransferred);
                break;
        }
    }
    return 0;
}

void InitIOCPSystem() {
    LoadConnectEx();
    g_hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int threads = si.dwNumberOfProcessors * 2;
    
    for (int i = 0; i < threads; ++i) {
        _beginthreadex(NULL, 0, IOCPWorkerThread, NULL, 0, NULL);
    }
    printf("[IOCP] System Initialized with %d threads.\n", threads);
}

// --- TCB Methods ---

TCB::TCB(const Quad& q) : quad(q), state(TcpState::CLOSED), local_seq(0), local_ack(0), remote_seq(0), client_sock(INVALID_SOCKET), is_sending(false), last_send_time(0) {
    local_seq = 0x12345678; 
}

TCB::~TCB() {
    if (client_sock != INVALID_SOCKET) {
        closesocket(client_sock);
    }
}

void TCB::InitIOCP() {
    client_sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (client_sock == INVALID_SOCKET) return;

    // Bind needed for ConnectEx
    sockaddr_in local = { 0 };
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;
    if (bind(client_sock, (sockaddr*)&local, sizeof(local)) != 0) {
        printf("[TCB] Bind failed %d\n", WSAGetLastError());
        return;
    }

    // Associate with IOCP
    CreateIoCompletionPort((HANDLE)client_sock, g_hIOCP, (ULONG_PTR)this, 0);

    // Start Connect
    if (!g_pConnectEx) LoadConnectEx();
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(SOCKS_SERVER_IP);
    addr.sin_port = htons(SOCKS_SERVER_PORT);

    recv_ctx.Reset(IO_OP::OP_CONNECT); // Reuse recv_ctx for connect
    
    // ConnectEx requires data buffer? No.
    BOOL ret = g_pConnectEx(client_sock, (sockaddr*)&addr, sizeof(addr), NULL, 0, NULL, &recv_ctx.overlapped);
    if (!ret && WSAGetLastError() != ERROR_IO_PENDING) {
        printf("[TCB] ConnectEx failed %d\n", WSAGetLastError());
    }
}

void TCB::OnConnectCompleted(BOOL success) {
    // Update socket context (required by ConnectEx)
    setsockopt(client_sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
    
    // printf("[TCB] Connected to Proxy via IOCP\n");
    StartSocksHandshake();
}

void TCB::StartSocksHandshake() {
    send_ctx.Reset(IO_OP::OP_SOCKS_HANDSHAKE_SEND);
    // 05 01 00
    send_ctx.buffer[0] = 0x05; send_ctx.buffer[1] = 0x01; send_ctx.buffer[2] = 0x00;
    send_ctx.wsaBuf.len = 3;
    
    WSASend(client_sock, &send_ctx.wsaBuf, 1, NULL, 0, &send_ctx.overlapped, NULL);
}

void TCB::StartSocksRequest() {
    send_ctx.Reset(IO_OP::OP_SOCKS_REQUEST_SEND);
    // 05 01 00 01 IP.. Port..
    uint8_t* buf = (uint8_t*)send_ctx.buffer;
    buf[0] = 0x05; buf[1] = 0x01; buf[2] = 0x00; buf[3] = 0x01;
    *(uint32_t*)(buf + 4) = quad.daddr;
    *(uint16_t*)(buf + 8) = quad.dport;
    send_ctx.wsaBuf.len = 10;
    
    WSASend(client_sock, &send_ctx.wsaBuf, 1, NULL, 0, &send_ctx.overlapped, NULL);
}

void TCB::StartRelay() {
    // printf("[TCB] SOCKS5 Established via IOCP. Starting Relay.\n");
    // Start Reading
    recv_ctx.Reset(IO_OP::OP_RELAY_RECV);
    DWORD flags = 0;
    WSARecv(client_sock, &recv_ctx.wsaBuf, 1, NULL, &flags, &recv_ctx.overlapped, NULL);
    
    // Trigger Send if any data pending
    DoSend();
}

void TCB::OnRecvCompleted(DWORD bytesTransferred) {
    if (bytesTransferred > 0) {
        // Push data to TAP queue
        std::lock_guard<std::mutex> lk(mtx);
        for (DWORD i = 0; i < bytesTransferred; ++i) {
            data_to_tap.push_back(recv_ctx.buffer[i]);
        }
    }
    
    // Continue Reading
    recv_ctx.Reset(IO_OP::OP_RELAY_RECV);
    DWORD flags = 0;
    WSARecv(client_sock, &recv_ctx.wsaBuf, 1, NULL, &flags, &recv_ctx.overlapped, NULL);
}

void TCB::OnSendCompleted(DWORD bytesTransferred) {
    is_sending = false;
    DoSend(); // Check if more data
}

void TCB::DoSend() {
    std::lock_guard<std::mutex> lk(mtx);
    if (is_sending || data_to_socks.empty()) return;
    
    // Prepare Send
    send_ctx.Reset(IO_OP::OP_RELAY_SEND);
    int count = 0;
    while (!data_to_socks.empty() && count < 4096) {
        send_ctx.buffer[count++] = data_to_socks.front();
        data_to_socks.pop_front();
    }
    send_ctx.wsaBuf.len = count;
    
    is_sending = true;
    WSASend(client_sock, &send_ctx.wsaBuf, 1, NULL, 0, &send_ctx.overlapped, NULL);
}

// --- Helper for packet construction (Keep existing logic) ---
static void send_tcp(HANDLE tap, const Quad& q, uint32_t seq, uint32_t ack, uint8_t flags, const void* data, int len, uint16_t mss = 0) {
    uint8_t frame[1514];
    int opt_len = (mss > 0) ? 4 : 0;
    int tcp_header_len = 20 + opt_len;
    
    memcpy(frame, TAP_MAC, 6);
    memcpy(frame + 6, TAP_MAC, 6); 
    *(uint16_t*)(frame + 12) = htons(0x0800);

    uint8_t* ip = frame + 14;
    uint8_t* tcp = ip + 20;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    uint16_t tot_len = 20 + tcp_header_len + len;
    *(uint16_t*)(ip + 2) = htons(tot_len);
    ip[8] = 64; ip[9] = 6;
    *(uint32_t*)(ip + 12) = q.daddr; 
    *(uint32_t*)(ip + 16) = q.saddr; 
    *(uint16_t*)(ip + 10) = checksum(ip, 20);

    memset(tcp, 0, 20 + opt_len); 
    *(uint16_t*)(tcp + 0) = q.dport; 
    *(uint16_t*)(tcp + 2) = q.sport; 
    *(uint32_t*)(tcp + 4) = htonl(seq); 
    *(uint32_t*)(tcp + 8) = htonl(ack);
    uint8_t offset_val = (tcp_header_len / 4) << 4;
    tcp[12] = offset_val; 
    tcp[13] = flags;
    *(uint16_t*)(tcp + 14) = htons(64240); 

    if (mss > 0) {
        tcp[20] = 0x02; tcp[21] = 0x04; *(uint16_t*)(tcp + 22) = htons(mss);
    }
    if (len > 0) memcpy(tcp + tcp_header_len, data, len);
    *(uint16_t*)(tcp + 16) = tcp_cksum(q.daddr, q.saddr, tcp, tcp_header_len + len);
    platform_send_frame(tap, frame, 14 + tot_len);
}

// --- Process Logic (Modified to call InitIOCP) ---

void process_tcp_packet(TCB& tcb, const Packet& pkt, HANDLE tap) {
    if (pkt.payload.size() < 20) return; 
    TcpHdr* tcp = (TcpHdr*)pkt.payload.data();
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack_seq);
    int head_len = (tcp->data_offset >> 4) * 4;
    int pay_len = pkt.pay_len - head_len;
    if (pay_len < 0) pay_len = 0;
    uint8_t flags = tcp->flags;

    if (flags & 0x04) { // RST
         tcb.state = TcpState::CLOSED;
         return;
    }

    if (flags & 0x02) { // SYN
        if (tcb.state == TcpState::CLOSED || tcb.state == TcpState::SYN_RCVD) {
            tcb.remote_seq = seq + 1;
            if (tcb.state == TcpState::CLOSED) {
                tcb.state = TcpState::SYN_RCVD;
                tcb.InitIOCP(); // <--- Start IOCP Connection here!
            }
            uint32_t syn_ack_seq = (tcb.state == TcpState::SYN_RCVD) ? tcb.local_seq - 1 : tcb.local_seq;
            send_tcp(tap, tcb.quad, syn_ack_seq, tcb.remote_seq, 0x12, NULL, 0, 1360); 
            if (tcb.state == TcpState::CLOSED) tcb.local_seq++; 
        }
        return; 
    }

    if (flags & 0x10) { // ACK
        if (tcb.state == TcpState::SYN_RCVD) {
            if (ack == tcb.local_seq) tcb.state = TcpState::ESTABLISHED;
        }
        
        if (tcb.state == TcpState::ESTABLISHED) {
            std::lock_guard<std::mutex> lk(tcb.mtx);
            // Simple ACK logic (retrans logic simplified out for clarity in this big refactor, add back if needed)
            // Ideally should clear unacked_data here.
            
            if (pay_len > 0) {
                tcb.remote_seq = seq + pay_len;
                const uint8_t* data_ptr = pkt.payload.data() + head_len;
                for(int i=0; i<pay_len; ++i) tcb.data_to_socks.push_back(data_ptr[i]);
                send_tcp(tap, tcb.quad, tcb.local_seq, tcb.remote_seq, 0x10, NULL, 0);
                
                // Trigger Send
                // We need to trigger this outside lock or be careful?
                // DoSend uses lock too. 
            }
        }
        if (pay_len > 0) tcb.DoSend(); // Trigger IOCP Send
    }

    if (flags & 0x01) { // FIN
        tcb.remote_seq = seq + pay_len + 1; 
        tcb.state = TcpState::CLOSE_WAIT;
        send_tcp(tap, tcb.quad, tcb.local_seq, tcb.remote_seq, 0x10, NULL, 0); 
    }
}

void flush_output(TCB& tcb, HANDLE tap) {
    if (tcb.state == TcpState::ESTABLISHED) {
        std::lock_guard<std::mutex> lk(tcb.mtx);
        if (!tcb.data_to_tap.empty()) {
            std::vector<uint8_t> buf;
            while (!tcb.data_to_tap.empty() && buf.size() < 1360) {
                buf.push_back(tcb.data_to_tap.front());
                tcb.data_to_tap.pop_front();
            }
            send_tcp(tap, tcb.quad, tcb.local_seq, tcb.remote_seq, 0x18, buf.data(), (int)buf.size());
            tcb.local_seq += (uint32_t)buf.size();
        }
    }
}