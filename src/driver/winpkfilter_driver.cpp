#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <iostream>
#include <algorithm>

#include "winpkfilter_driver.h"
#include "app_config.h"
#include "logger.h"
#include "nat_manager.h"
#include "geo_checker.h"
#include "tls_parser.h"
#include "proxy_tcp.h"

// --- Protocol Header Definitions ---
#include <pshpack1.h>
typedef struct _IP_HEADER {
    UCHAR   Ver_HLen;
    UCHAR   TOS;
    USHORT  Len;
    USHORT  ID;
    USHORT  Flags_Frag;
    UCHAR   TTL;
    UCHAR   Proto;
    USHORT  Csum;
    ULONG   SrcAddr;
    ULONG   DstAddr;
} IP_HEADER, * PIP_HEADER;

typedef struct _TCP_HEADER {
    USHORT  SrcPort;
    USHORT  DstPort;
    ULONG   SeqNum;
    ULONG   AckNum;
    UCHAR   HdrLen;
    UCHAR   Flags;
    USHORT  WinSize;
    USHORT  Csum;
    USHORT  UrgPtr;
} TCP_HEADER, * PTCP_HEADER;

typedef struct _UDP_HEADER {
    USHORT  SrcPort;
    USHORT  DstPort;
    USHORT  Len;
    USHORT  Csum;
} UDP_HEADER, * PUDP_HEADER;

typedef struct _ICMP_HEADER {
    UCHAR   Type;
    UCHAR   Code;
    USHORT  Csum;
    USHORT  Id;
    USHORT  Seq;
} ICMP_HEADER, * PICMP_HEADER;

typedef struct _ARP_HEADER {
    USHORT  HwType;
    USHORT  ProtoType;
    UCHAR   HwLen;
    UCHAR   ProtoLen;
    USHORT  OpCode;
    UCHAR   SrcMac[6];
    ULONG   SrcIp;
    UCHAR   DstMac[6];
    ULONG   DstIp;
} ARP_HEADER, * PARP_HEADER;

typedef struct _PSD_HEADER {
    ULONG  SrcAddr;
    ULONG  DstAddr;
    UCHAR  Zero;
    UCHAR  Proto;
    USHORT Len;
} PSD_HEADER, * PPSD_HEADER;

typedef struct _IPV6_HEADER {
    ULONG   Ver_Traffic_Flow;
    USHORT  PayloadLen;
    UCHAR   NextHeader;
    UCHAR   HopLimit;
    UCHAR   SrcAddr[16];
    UCHAR   DstAddr[16];
} IPV6_HEADER, * PIPV6_HEADER;

typedef struct _TCPV6_PSD_HEADER {
    UCHAR   SrcAddr[16];
    UCHAR   DstAddr[16];
    ULONG   PayloadLen;
    UCHAR   Zero[3];
    UCHAR   NextHeader;
} TCPV6_PSD_HEADER, * PTCPV6_PSD_HEADER;

#include <poppack.h>

const USHORT ETHERTYPE_IP = 0x0800;
const USHORT ETHERTYPE_IPV6 = 0x86DD;
const USHORT ETHERTYPE_ARP = 0x0806;
const USHORT NAT_TARGET_PORT = 3080;

#pragma comment(lib, "ndisapilib.lib")
#pragma comment(lib, "iphlpapi.lib")

#include "dhcp_server.h"

extern DhcpServer* g_dhcp_server_ptr;  // 引用外部定义的全局变量

static uint32_t csum_partial(const void* data, int len, uint32_t start_sum) {
    const uint16_t* ptr = (const uint16_t*)data;
    uint32_t sum = start_sum;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len > 0) { sum += *(const uint8_t*)ptr; }
    return sum;
}

static uint16_t csum_finalize(uint32_t sum) {
    while (sum >> 16) { sum = (sum & 0xFFFF) + (sum >> 16); }
    uint16_t result = (uint16_t)(~sum);
    return (result == 0) ? 0xFFFF : result;
}

// 增量更新16位字段的校验和
static void incremental_checksum_update(uint16_t* checksum, uint16_t old_val, uint16_t new_val) {
    if (*checksum == 0) return; // Skip if no checksum
    uint32_t sum = (~(*checksum)) & 0xFFFF;
    sum += (~old_val) & 0xFFFF;
    sum += new_val;
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t result = ~((uint16_t)sum);
    *checksum = (result == 0) ? 0xFFFF : result;
}

// 增量更新32位字段的校验和
static void incremental_checksum_update(uint16_t* checksum, uint32_t old_val, uint32_t new_val) {
    if (*checksum == 0) return; // Skip if no checksum
    uint32_t sum = (~(*checksum)) & 0xFFFF;
    sum += (~(old_val & 0xFFFF)) & 0xFFFF;
    sum += (~(old_val >> 16)) & 0xFFFF;
    sum += (new_val & 0xFFFF);
    sum += (new_val >> 16);
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t result = ~((uint16_t)sum);
    *checksum = (result == 0) ? 0xFFFF : result;
}

static void recalculate_ip_checksum(PIP_HEADER ip) {
    ip->Csum = 0;
    ip->Csum = csum_finalize(csum_partial(ip, (ip->Ver_HLen & 0x0F) * 4, 0));
}

static void recalculate_tcp_udp_checksum(PIP_HEADER ip) {
    int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;
    int payload_len = ntohs(ip->Len) - ip_hdr_len;
    if (payload_len < 0) return;

    PSD_HEADER psd;
    psd.SrcAddr = ip->SrcAddr;
    psd.DstAddr = ip->DstAddr;
    psd.Zero = 0;
    psd.Proto = ip->Proto;
    psd.Len = htons((USHORT)payload_len);

    uint32_t sum = csum_partial(&psd, sizeof(psd), 0);

    if (ip->Proto == IPPROTO_TCP) {
        PTCP_HEADER tcp = (PTCP_HEADER)((uint8_t*)ip + ip_hdr_len);
        tcp->Csum = 0;
        tcp->Csum = csum_finalize(csum_partial(tcp, payload_len, sum));
    }
    else if (ip->Proto == IPPROTO_UDP) {
        PUDP_HEADER udp = (PUDP_HEADER)((uint8_t*)ip + ip_hdr_len);
        udp->Csum = 0;
        udp->Csum = csum_finalize(csum_partial(udp, payload_len, sum));
    }
    else if (ip->Proto == IPPROTO_ICMP) {
        PICMP_HEADER icmp = (PICMP_HEADER)((uint8_t*)ip + ip_hdr_len);
        icmp->Csum = 0;
        icmp->Csum = csum_finalize(csum_partial(icmp, payload_len, 0));
    }
}

static bool patch_dhcp_ack_dns(uint8_t* frame, size_t& frame_len, size_t capacity, uint32_t dns_ip) {
    if (frame_len < 14 + sizeof(IP_HEADER) + sizeof(UDP_HEADER) + 240) return false;

    PIP_HEADER ip = (PIP_HEADER)(frame + 14);
    const int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;
    if (ip_hdr_len < 20 || frame_len < 14 + ip_hdr_len + sizeof(UDP_HEADER) + 240) return false;
    if (ip->Proto != IPPROTO_UDP) return false;

    PUDP_HEADER udp = (PUDP_HEADER)((uint8_t*)ip + ip_hdr_len);
    if (ntohs(udp->SrcPort) != 67 || ntohs(udp->DstPort) != 68) return false;

    const size_t udp_len = ntohs(udp->Len);
    if (udp_len < sizeof(UDP_HEADER) + 240) return false;
    if (14 + ip_hdr_len + udp_len > frame_len) return false;

    uint8_t* dhcp = (uint8_t*)udp + sizeof(UDP_HEADER);
    size_t dhcp_len = udp_len - sizeof(UDP_HEADER);
    if (dhcp[236] != 0x63 || dhcp[237] != 0x82 || dhcp[238] != 0x53 || dhcp[239] != 0x63) return false;

    bool is_ack = false;
    bool has_dns = false;
    size_t end_pos = SIZE_MAX;
    size_t pos = 240;
    while (pos < dhcp_len) {
        const uint8_t code = dhcp[pos];
        if (code == 0) {
            ++pos;
            continue;
        }
        if (code == 255) {
            end_pos = pos;
            break;
        }
        if (pos + 1 >= dhcp_len) return false;
        const uint8_t opt_len = dhcp[pos + 1];
        if (pos + 2 + opt_len > dhcp_len) return false;
        if (code == 53 && opt_len == 1 && dhcp[pos + 2] == 5) is_ack = true;
        if (code == 6 && opt_len >= 4) has_dns = true;
        pos += 2 + opt_len;
    }

    if (!is_ack || has_dns || end_pos == SIZE_MAX) return false;
    constexpr size_t insert_len = 6; // option, length, IPv4 DNS
    if (frame_len + insert_len > capacity) return false;

    uint8_t* insert = dhcp + end_pos;
    memmove(insert + insert_len, insert, dhcp_len - end_pos);
    insert[0] = 6;
    insert[1] = 4;
    memcpy(insert + 2, &dns_ip, 4);

    dhcp_len += insert_len;
    frame_len += insert_len;

    ip->Len = htons((USHORT)(ip_hdr_len + sizeof(UDP_HEADER) + dhcp_len));
    udp->Len = htons((USHORT)(sizeof(UDP_HEADER) + dhcp_len));
    recalculate_ip_checksum(ip);
    udp->Csum = 0; // IPv4 UDP checksum is optional; avoid stale checksum after option insertion.
    return true;
}

// Smart worker dispatch: Symmetric Hash (Client IP ^ Client Port)
// This ensures that all packets for the same flow (both directions) go to the same worker.
// WARNING: This assumes NO IP FRAGMENTATION. If packets are fragmented, port info is missing
// in subsequent fragments, which might lead to mis-hashing.
static uint32_t get_target_worker(const char* packet, size_t length, uint32_t device_flags, uint32_t num_workers) {
    if (length < 14) return 0;

    USHORT ether_type = ntohs(*(USHORT*)(packet + 12));
    if (ether_type != ETHERTYPE_IP) {
        // Non-IP packets (ARP, IPv6, EAPOL, etc.)
        // Fallback: Hash the "Client" MAC to keep the session pinned to one worker.
        const uint8_t* mac;
        if (device_flags == PACKET_FLAG_ON_SEND) {
            mac = (const uint8_t*)(packet + 0); // Dst MAC (Client)
        }
        else {
            mac = (const uint8_t*)(packet + 6); // Src MAC (Client)
        }
        uint32_t hash = mac[0] ^ mac[1] ^ mac[2] ^ mac[3] ^ mac[4] ^ mac[5];
        return hash % num_workers;
    }

    if (length < 14 + sizeof(IP_HEADER)) return 0;
    PIP_HEADER ip = (PIP_HEADER)(packet + 14);
    int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;

    uint32_t client_ip;
    uint32_t client_port = 0; // Use 32-bit for convenient XOR

    if (device_flags == PACKET_FLAG_ON_SEND) {
        // Outbound (Stack -> Adapter): Destination is Client
        client_ip = ip->DstAddr;

        // Attempt to extract Dest Port (Client Port)
        if (ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP) {
            // Check if packet is large enough to contain the port
            if (length >= 14 + ip_hdr_len + 4) {
                // DstPort is at offset 2 in TCP/UDP header
                client_port = *(uint16_t*)(packet + 14 + ip_hdr_len + 2);
            }
        }
    }
    else {
        // Inbound (Adapter -> Stack): Source is Client
        client_ip = ip->SrcAddr;

        // Attempt to extract Src Port (Client Port)
        if (ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP) {
            // Check if packet is large enough to contain the port
            if (length >= 14 + ip_hdr_len + 2) {
                // SrcPort is at offset 0 in TCP/UDP header
                client_port = *(uint16_t*)(packet + 14 + ip_hdr_len);
            }
        }
    }

    // Symmetric Hash: Client IP ^ Client Port
    // If it's a fragment without port, client_port will be 0, degrading to IP-only hash.
    return (client_ip ^ client_port) % num_workers;
}

enum WorkerStage : uint32_t {
    WORKER_STAGE_START = 0,
    WORKER_STAGE_SPIN = 1,
    WORKER_STAGE_WAIT = 2,
    WORKER_STAGE_POP = 3,
    WORKER_STAGE_PROCESS = 4,
    WORKER_STAGE_FLUSH_ADAPTER = 5,
    WORKER_STAGE_FLUSH_STACK = 6,
    WORKER_STAGE_IDLE = 7,
    WORKER_STAGE_EXIT = 8,
};

static const char* worker_stage_name(uint32_t stage) {
    switch (stage) {
    case WORKER_STAGE_START: return "start";
    case WORKER_STAGE_SPIN: return "spin";
    case WORKER_STAGE_WAIT: return "wait";
    case WORKER_STAGE_POP: return "pop";
    case WORKER_STAGE_PROCESS: return "process";
    case WORKER_STAGE_FLUSH_ADAPTER: return "flush_adapter";
    case WORKER_STAGE_FLUSH_STACK: return "flush_stack";
    case WORKER_STAGE_IDLE: return "idle";
    case WORKER_STAGE_EXIT: return "exit";
    default: return "unknown";
    }
}

WinPkFilterDriver::WinPkFilterDriver()
    : m_adapter_handle(nullptr), m_wait_event(nullptr), m_running(false), m_gateway_ip(0), m_ics_gateway_ip(0), m_pass_ics_control(false) {
    CNdisApi::SetPoolSize(524288);

    m_num_workers = (std::max)(1u, std::thread::hardware_concurrency());
    for (unsigned int i = 0; i < m_num_workers; ++i) {
        m_worker_queues.push_back(std::make_unique<WorkerQueue>());
    }
    m_read_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    for (int i = 0; i < BATCH_SIZE; ++i) m_read_buffers[i] = nullptr;
    m_send_buffer = new INTERMEDIATE_BUFFER();
    memset(m_adapter_mac, 0, 6);
    m_last_stat_time = std::chrono::steady_clock::now();
}

WinPkFilterDriver::~WinPkFilterDriver() {
    stop();
    for (int i = 0; i < BATCH_SIZE; ++i) if (m_read_buffers[i]) PacketPool::instance().release(m_read_buffers[i]);
    free(m_read_request); delete m_send_buffer;
}

std::vector<std::pair<std::string, std::string>> WinPkFilterDriver::get_adapters() {
    std::vector<std::pair<std::string, std::string>> result;
    CNdisApi api; if (!api.IsDriverLoaded()) return result;
    TCP_AdapterList adapters;
    if (api.GetTcpipBoundAdaptersInfo(&adapters)) {
        for (UINT i = 0; i < adapters.m_nAdapterCount; ++i)
            result.push_back({ (char*)adapters.m_szAdapterNameList[i], (char*)adapters.m_szAdapterNameList[i] });
    }
    return result;
}

bool WinPkFilterDriver::start_batch(const std::string& adapter_name, BatchPacketHandler handler, bool pass_ics_control) {
    if (!m_ndis_api.IsDriverLoaded()) return false;
    for (int i = 0; i < BATCH_SIZE; ++i) if (!m_read_buffers[i]) {
        m_read_buffers[i] = PacketPool::instance().acquire();
        m_read_request->EthPacket[i].Buffer = m_read_buffers[i];
    }
    TCP_AdapterList adapters; if (!m_ndis_api.GetTcpipBoundAdaptersInfo(&adapters)) return false;
    bool found = false;
    std::string target_lower = adapter_name; std::transform(target_lower.begin(), target_lower.end(), target_lower.begin(), ::tolower);
    for (UINT i = 0; i < adapters.m_nAdapterCount; ++i) {
        std::string current_lower = (char*)adapters.m_szAdapterNameList[i]; std::transform(current_lower.begin(), current_lower.end(), current_lower.begin(), ::tolower);
        if (current_lower.find(target_lower) != std::string::npos || target_lower.find(current_lower) != std::string::npos) {
            m_adapter_handle = adapters.m_nAdapterHandle[i]; found = true; break;
        }
    }
    if (!found) return false;
    m_pass_ics_control = pass_ics_control;
    m_gateway_ip = inet_addr(g_config.gateway_ip.c_str());
    m_ics_gateway_ip = inet_addr(WIFI_AP_GATEWAY_IP);
    get_adapter_mac(adapter_name, m_adapter_mac);
    m_batch_handler = handler;
    m_wait_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    m_ndis_api.SetPacketEvent(m_adapter_handle, m_wait_event);
    DWORD tunnel_flags = MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL;
    ADAPTER_MODE mode = { m_adapter_handle, tunnel_flags };
    m_ndis_api.SetAdapterMode(&mode);
    m_running = true;
    m_read_request->hAdapterHandle = m_adapter_handle;

    m_reader_thread = std::thread(&WinPkFilterDriver::reader_loop, this);
    SetThreadPriority(m_reader_thread.native_handle(), THREAD_PRIORITY_ABOVE_NORMAL);

    for (unsigned int i = 0; i < m_num_workers; ++i) {
        m_worker_threads.emplace_back(&WinPkFilterDriver::worker_loop, this, i);
        SetThreadPriority(m_worker_threads.back().native_handle(), THREAD_PRIORITY_ABOVE_NORMAL);
    }
    return true;
}

void WinPkFilterDriver::stop() {
    m_running = false;
    if (m_wait_event) SetEvent(m_wait_event);
    for (auto& q : m_worker_queues) q->cv.notify_all();
    if (m_reader_thread.joinable()) m_reader_thread.join();
    for (auto& w : m_worker_threads) if (w.joinable()) w.join();

    if (m_adapter_handle) {
        ADAPTER_MODE mode = { m_adapter_handle, 0 }; m_ndis_api.SetAdapterMode(&mode);
        m_ndis_api.SetPacketEvent(m_adapter_handle, nullptr); m_adapter_handle = nullptr;
    }
    if (m_wait_event) { CloseHandle(m_wait_event); m_wait_event = nullptr; }
    for (int i = 0; i < BATCH_SIZE; ++i) {
        if (m_read_request->EthPacket[i].Buffer) {
            PacketPool::instance().release(m_read_request->EthPacket[i].Buffer);
            m_read_request->EthPacket[i].Buffer = nullptr;
        }
    }
}

void WinPkFilterDriver::worker_loop(unsigned int worker_id) {
    // Local batch requests
    PETH_M_REQUEST to_adapter_req = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    PETH_M_REQUEST to_stack_req = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    to_adapter_req->hAdapterHandle = m_adapter_handle;
    to_stack_req->hAdapterHandle = m_adapter_handle;

    auto mark_stage = [&](uint32_t stage, uint32_t batch = 0) {
        if (worker_id >= MAX_WORKERS) return;
        uint64_t now_ms = GetTickCount64();
        m_stat_worker_stage[worker_id].store(stage, std::memory_order_relaxed);
        m_stat_worker_stage_ms[worker_id].store(now_ms, std::memory_order_relaxed);
        m_stat_worker_seen_ms[worker_id].store(now_ms, std::memory_order_relaxed);
        m_stat_worker_batch[worker_id].store(batch, std::memory_order_relaxed);
    };

    mark_stage(WORKER_STAGE_START);

    auto flush_packets = [&](PETH_M_REQUEST req, bool to_adapter) {
        if (req->dwPacketsNumber > 0) {
            mark_stage(to_adapter ? WORKER_STAGE_FLUSH_ADAPTER : WORKER_STAGE_FLUSH_STACK, req->dwPacketsNumber);
            BOOL ok = to_adapter ? m_ndis_api.SendPacketsToAdapter(req) : m_ndis_api.SendPacketsToMstcp(req);
            if (!ok) {
                if (to_adapter) m_stat_batch_adapter_fail++;
                else m_stat_batch_stack_fail++;
            }

            // Extract pointers for batch release
            PINTERMEDIATE_BUFFER release_ptrs[BATCH_SIZE];
            for (unsigned int i = 0; i < req->dwPacketsNumber; ++i) {
                release_ptrs[i] = req->EthPacket[i].Buffer;
            }
            PacketPool::instance().release_batch(release_ptrs, req->dwPacketsNumber);

            req->dwPacketsNumber = 0;
        }
        };

    while (m_running) {
        // High-Performance Hybrid Spin-Wait Strategy
        mark_stage(WORKER_STAGE_SPIN);
        bool has_work = false;
        for (int spin = 0; spin < 4000; ++spin) {
            if (m_worker_queues[worker_id]->head.load(std::memory_order_acquire) != 
                m_worker_queues[worker_id]->tail.load(std::memory_order_relaxed)) {
                has_work = true;
                break;
            }
            if (spin < 1000) {
                _mm_pause(); // Very fast hardware-level pause (nanoseconds)
            } else if (spin < 3500) {
                // Do nothing, just tight loop
            } else {
                std::this_thread::yield(); // Final effort before sleeping
            }
        }

        if (!has_work && m_running) {
            mark_stage(WORKER_STAGE_WAIT);
            std::unique_lock<std::mutex> lock(m_worker_queues[worker_id]->mtx);
            m_worker_queues[worker_id]->cv.wait_for(lock, std::chrono::milliseconds(1), [&] {
                return !m_running || (m_worker_queues[worker_id]->head.load(std::memory_order_acquire) != 
                                     m_worker_queues[worker_id]->tail.load(std::memory_order_relaxed));
            });
        }

        if (!m_running) break;

        auto start_time = std::chrono::steady_clock::now();
        to_adapter_req->dwPacketsNumber = 0;
        to_stack_req->dwPacketsNumber = 0;

        // Process packets in larger batches (512) for peak throughput
        PINTERMEDIATE_BUFFER batch_bufs[BATCH_SIZE];
        size_t popped_count;
        while ((popped_count = m_worker_queues[worker_id]->pop_batch(batch_bufs, BATCH_SIZE)) > 0) {
            mark_stage(WORKER_STAGE_POP, (uint32_t)popped_count);
            if (worker_id < MAX_WORKERS) m_stat_worker_out_pkts[worker_id].fetch_add(popped_count, std::memory_order_relaxed);
            mark_stage(WORKER_STAGE_PROCESS, (uint32_t)popped_count);
            for (size_t i = 0; i < popped_count; ++i) {
                PINTERMEDIATE_BUFFER b = batch_bufs[i];
                Packet p{ RawPacketPtr(b), (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) };
                unsigned char* buffer = p.data->m_IBuffer;
                size_t length = p.data->m_Length;
                bool handled = false;
                bool to_adapter = false;

                if (length >= 14) {
                    USHORT ether_type = ntohs(*(USHORT*)(buffer + 12));
                    if (ether_type == ETHERTYPE_IP && length >= 34) {
                        PIP_HEADER ip = (PIP_HEADER)(buffer + 14);
                        int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;
                        bool is_fragment = (ntohs(ip->Flags_Frag) & 0x1FFF) != 0;

                        // --- Intercept Inbound (Adapter -> Proxy) ---
                        if (!p.outbound && (ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP) && ip->SrcAddr != m_gateway_ip) {
                            if (!is_fragment) {
                                bool should_intercept = true;
                                if (ip->DstAddr == m_gateway_ip) {
                                    USHORT dport = (ip->Proto == IPPROTO_TCP) ? ((PTCP_HEADER)((char*)ip + ip_hdr_len))->DstPort : ((PUDP_HEADER)((char*)ip + ip_hdr_len))->DstPort;
                                    if (dport == htons(NAT_TARGET_PORT)) {
                                        should_intercept = false;
                                        // Already targeting proxy, skip expensive recalculation
                                    }
                                }

                                if (should_intercept) {
                                    uint32_t old_dst_ip = ip->DstAddr;
                                    if (ip->Proto == IPPROTO_TCP) {
                                        PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + ip_hdr_len);
                                        uint16_t old_dst_port = tcp->DstPort;
                                        NatManager::instance().create_tcp_mapping(NatManager::make_key(ip->SrcAddr, tcp->SrcPort), { old_dst_ip, old_dst_port, ip->SrcAddr }, worker_id);

                                        ip->DstAddr = m_gateway_ip;
                                        tcp->DstPort = htons(NAT_TARGET_PORT);
                                        incremental_checksum_update(&ip->Csum, old_dst_ip, ip->DstAddr);
                                        incremental_checksum_update(&tcp->Csum, old_dst_ip, ip->DstAddr);
                                        incremental_checksum_update(&tcp->Csum, old_dst_port, tcp->DstPort);

                                        to_adapter = false;
                                        handled = true;
                                    }
                                    else { // UDP
                                        PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + ip_hdr_len);
                                        uint16_t virtual_port = NatManager::instance().allocate_udp_virtual_port({ ip->SrcAddr, udp->SrcPort, ip->DstAddr, udp->DstPort }, { old_dst_ip, udp->DstPort, ip->SrcAddr });
                                        if (virtual_port != 0) {
                                            uint32_t upstream_nbo = 0;
                                            inet_pton(AF_INET, g_config.upstream_ip.c_str(), &upstream_nbo);
                                            if (ntohs(udp->DstPort) == g_config.upstream_port ||
                                                old_dst_ip == upstream_nbo ||
                                                old_dst_ip == htonl(INADDR_LOOPBACK)) {
                                                LOG_DEBUG("[NATUDP] UDP mapping trace src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u dst_raw=%08X:%04X upstream_match=%d loopback=%d vport=%u worker=%zu",
                                                    ip->SrcAddr & 0xFF, (ip->SrcAddr >> 8) & 0xFF, (ip->SrcAddr >> 16) & 0xFF, (ip->SrcAddr >> 24) & 0xFF, ntohs(udp->SrcPort),
                                                    old_dst_ip & 0xFF, (old_dst_ip >> 8) & 0xFF, (old_dst_ip >> 16) & 0xFF, (old_dst_ip >> 24) & 0xFF, ntohs(udp->DstPort),
                                                    ntohl(old_dst_ip), ntohs(udp->DstPort),
                                                    (old_dst_ip == upstream_nbo && ntohs(udp->DstPort) == g_config.upstream_port) ? 1 : 0,
                                                    old_dst_ip == htonl(INADDR_LOOPBACK) ? 1 : 0,
                                                    virtual_port,
                                                    worker_id);
                                            }
                                            uint16_t old_dst_port = udp->DstPort;
                                            uint16_t old_src_port = udp->SrcPort;
                                            ip->DstAddr = m_gateway_ip;
                                            udp->DstPort = htons(NAT_TARGET_PORT);
                                            udp->SrcPort = htons(virtual_port);
                                            incremental_checksum_update(&ip->Csum, old_dst_ip, ip->DstAddr);
                                            incremental_checksum_update(&udp->Csum, old_dst_ip, ip->DstAddr);
                                            incremental_checksum_update(&udp->Csum, old_dst_port, udp->DstPort);
                                            incremental_checksum_update(&udp->Csum, old_src_port, udp->SrcPort);

                                            to_adapter = false;
                                            handled = true;
                                        }
                                        else {
                                            handled = true; // Dropped
                                        }
                                    }
                                }
                            }
                        }
                        // --- Restore Outbound (Proxy -> Adapter) ---
                        else if (p.outbound && (ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP)) {
                            int sport = (ip->Proto == IPPROTO_TCP) ? ntohs(((PTCP_HEADER)((char*)ip + ip_hdr_len))->SrcPort) : ntohs(((PUDP_HEADER)((char*)ip + ip_hdr_len))->SrcPort);
                            int dport = (ip->Proto == IPPROTO_TCP) ? ntohs(((PTCP_HEADER)((char*)ip + ip_hdr_len))->DstPort) : ntohs(((PUDP_HEADER)((char*)ip + ip_hdr_len))->DstPort);

                            bool is_proxy_reply = (sport == NAT_TARGET_PORT);

                            if (is_proxy_reply) {
                                if (ip->Proto == IPPROTO_TCP) {
                                    PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + ip_hdr_len);
                                    auto od = NatManager::instance().get_mapping(NatManager::make_key(ip->DstAddr, tcp->DstPort));
                                    if (od) {
                                        uint32_t old_src_ip = ip->SrcAddr;
                                        ip->SrcAddr = od->ip;
                                        uint16_t old_src_port = tcp->SrcPort;
                                        tcp->SrcPort = od->port;

                                        incremental_checksum_update(&ip->Csum, old_src_ip, ip->SrcAddr);
                                        incremental_checksum_update(&tcp->Csum, old_src_ip, ip->SrcAddr);
                                        incremental_checksum_update(&tcp->Csum, old_src_port, tcp->SrcPort);
                                    }
                                    else {
                                        recalculate_ip_checksum(ip); recalculate_tcp_udp_checksum(ip);
                                    }
                                }
                                else { // UDP
                                    PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + ip_hdr_len);
                                    auto key4 = NatManager::instance().get_udp_key_by_virtual_port(ntohs(udp->DstPort));
                                    if (key4) {
                                        uint32_t old_src_ip = ip->SrcAddr;
                                        uint16_t old_src_port = udp->SrcPort;
                                        uint16_t old_dst_port = udp->DstPort;

                                        // key4 is the original inbound key: { phone_ip, phone_port, remote_ip, remote_port }
                                        // We are restoring the reply: { remote_ip, remote_port } -> { phone_ip, phone_port }
                                        ip->SrcAddr = key4->dst_ip;    // Restore to remote server IP
                                        udp->SrcPort = key4->dst_port; // Restore to remote server port
                                        udp->DstPort = key4->src_port; // Restore to phone's original source port

                                        incremental_checksum_update(&ip->Csum, old_src_ip, ip->SrcAddr);
                                        incremental_checksum_update(&udp->Csum, old_src_ip, ip->SrcAddr);
                                        incremental_checksum_update(&udp->Csum, old_src_port, udp->SrcPort);
                                        incremental_checksum_update(&udp->Csum, old_dst_port, udp->DstPort);
                                    }
                                }
                                to_adapter = true;
                                handled = true;
                            }
                        }
                    }
                }

                if (!handled) {
                    to_adapter = p.outbound;
                }

                PINTERMEDIATE_BUFFER b_raw = p.data.release();
                if (b_raw) {
                        if (to_adapter) {
                            to_adapter_req->EthPacket[to_adapter_req->dwPacketsNumber++].Buffer = b_raw;
                            if (to_adapter_req->dwPacketsNumber >= 64) {
                                flush_packets(to_adapter_req, true);
                            }
                        }
                        else {
                            to_stack_req->EthPacket[to_stack_req->dwPacketsNumber++].Buffer = b_raw;
                            if (to_stack_req->dwPacketsNumber >= 64) {
                                flush_packets(to_stack_req, false);
                            }
                        }
                }
            }
        }

        // Flush remaining packets after the queue has been fully drained
        flush_packets(to_adapter_req, true);
        flush_packets(to_stack_req, false);

        if (worker_id < MAX_WORKERS) m_stat_worker_loops[worker_id].fetch_add(1, std::memory_order_relaxed);
        m_stat_work_time_us += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time).count();
        mark_stage(WORKER_STAGE_IDLE);
    }
    mark_stage(WORKER_STAGE_EXIT);
    free(to_adapter_req);
    free(to_stack_req);
}

void WinPkFilterDriver::reader_loop() {
    HANDLE wait_events[1] = { m_wait_event };
    while (m_running) {
        WaitForMultipleObjects(1, wait_events, FALSE, 10);
        if (!m_running) break;

        // 1. Read & Dispatch
        bool data_available = true;
        for (int r = 0; r < 8 && m_running && data_available; ++r) { // Max 8 batches (4096 pkts) per event
            m_read_request->dwPacketsNumber = BATCH_SIZE;
            if (m_ndis_api.ReadPackets(m_read_request)) {
                if (m_read_request->dwPacketsSuccess > 0) {
                    // Optimized single-pass dispatch: O(N + W)
                    uint32_t worker_packet_counts[128] = { 0 };
                    uint32_t packet_worker_ids[BATCH_SIZE];
                    uint32_t packet_original_indices[BATCH_SIZE];
                    uint32_t ready_to_dispatch = 0;

                    for (unsigned int i = 0; i < m_read_request->dwPacketsSuccess; ++i) {
                        PINTERMEDIATE_BUFFER b = m_read_request->EthPacket[i].Buffer;
                        
                        // 1. Basic Stats
                        if (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) {
                            m_stat_ul_pkts++; m_stat_ul_bytes += b->m_Length;
                        } else {
                            m_stat_dl_pkts++; m_stat_dl_bytes += b->m_Length;
                        }

                        // 2. Fast Path logic
                        bool handled = false;
                        if (b->m_Length >= 14) {
                            unsigned char* buffer = b->m_IBuffer;
                            USHORT ether_type = ntohs(*(USHORT*)(buffer + 12));

                            if (ether_type != ETHERTYPE_IP) {
                                if (ether_type == ETHERTYPE_IPV6) {
                                    m_stat_ipv6_drop++;
                                    handled = true; // Drop IPv6 for now
                                } else if (ether_type == ETHERTYPE_ARP) {
                                    if (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) {
                                        this->send_to_adapter((const char*)buffer, b->m_Length);
                                    } else {
                                        this->send_to_mstcp((const char*)buffer, b->m_Length);
                                    }
                                    m_stat_arp_pass++;
                                    handled = true;
                                } else if (ether_type == 0x888E) { // EAPOL
                                    if (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) this->send_to_adapter((const char*)buffer, b->m_Length);
                                    else this->send_to_mstcp((const char*)buffer, b->m_Length);
                                    m_stat_eapol_pass++;
                                    handled = true;
                                }
                            } else if (b->m_Length >= 34) {
                                PIP_HEADER ip = (PIP_HEADER)(buffer + 14);
                                if (!m_pass_ics_control && m_ics_gateway_ip != 0 && ip->SrcAddr == m_ics_gateway_ip) {
                                    m_stat_ics_drop++;
                                    handled = true;
                                } else if (ip->Proto == IPPROTO_ICMP && b->m_dwDeviceFlags != PACKET_FLAG_ON_SEND && b->m_Length >= 14 + ((ip->Ver_HLen & 0x0F) * 4) + sizeof(ICMP_HEADER)) {
                                    PICMP_HEADER icmp = (PICMP_HEADER)(buffer + 14 + ((ip->Ver_HLen & 0x0F) * 4));
                                    if (icmp->Type == 8) { // Echo Request
                                        uint8_t tmac[6]; memcpy(tmac, buffer, 6); memcpy(buffer, buffer + 6, 6); memcpy(buffer + 6, tmac, 6);
                                        ULONG tip = ip->SrcAddr; uint32_t old_dst = ip->DstAddr;
                                        ip->SrcAddr = ip->DstAddr; ip->DstAddr = tip; icmp->Type = 0;
                                        incremental_checksum_update(&ip->Csum, (uint32_t)tip, (uint32_t)ip->SrcAddr);
                                        incremental_checksum_update(&ip->Csum, (uint32_t)old_dst, (uint32_t)ip->DstAddr);
                                        incremental_checksum_update(&icmp->Csum, (uint16_t)htons(0x0800), (uint16_t)htons(0x0000));
                                        this->send_to_adapter((const char*)buffer, b->m_Length);
                                        m_stat_icmp_reply++;
                                        handled = true;
                                    }
                                } else if (ip->Proto == IPPROTO_UDP) {
                                    PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + ((ip->Ver_HLen & 0x0F) * 4));
                                    USHORT sp = ntohs(udp->SrcPort), dp = ntohs(udp->DstPort);
                                    if (sp == 67 || dp == 67 || sp == 68 || dp == 68) {
                                        if (m_pass_ics_control) {
                                            size_t patched_len = b->m_Length;
                                            if (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND && sp == 67 && dp == 68 &&
                                                patch_dhcp_ack_dns(buffer, patched_len, sizeof(b->m_IBuffer), m_gateway_ip)) {
                                                b->m_Length = (ULONG)patched_len;
                                                m_stat_dhcp_patch++;
                                                LOG_WARN("[DHCP] patched ACK with DNS=%s", g_config.gateway_ip.c_str());
                                            }
                                            if (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) {
                                                this->send_to_adapter((const char*)buffer, b->m_Length);
                                            } else {
                                                this->send_to_mstcp((const char*)buffer, b->m_Length);
                                            }
                                            m_stat_dhcp_pass++;
                                            handled = true;
                                        } else if (g_dhcp_server_ptr) {
                                            DhcpResponse dhcp_r = g_dhcp_server_ptr->handle_request_buffer((const char*)udp + sizeof(UDP_HEADER), b->m_Length);
                                            if (dhcp_r.length > 0) this->send_dhcp_response(((uint8_t*)ip) - 8, m_gateway_ip, dhcp_r, m_adapter_mac);
                                            m_stat_dhcp_pass++;
                                            handled = true;
                                        }
                                    } else if (sp == 1900 || dp == 1900 || sp == 5353 || dp == 5353 || sp == 137 || dp == 137 || sp == 138 || dp == 138) {
                                        if (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) {
                                            this->send_to_adapter((const char*)buffer, b->m_Length);
                                        } else {
                                            this->send_to_mstcp((const char*)buffer, b->m_Length);
                                        }
                                        m_stat_lan_discovery_pass++;
                                        handled = true;
                                    } else if (b->m_dwDeviceFlags != PACKET_FLAG_ON_SEND && sp != 53 && dp != 53 && ProxyTCP::pressure_high()) {
                                        if (dp == 443) {
                                            this->send_icmp_port_unreachable(ip->SrcAddr, udp->SrcPort, ip->DstAddr, udp->DstPort);
                                        }
                                        m_stat_dropped_pkts++;
                                        m_stat_pressure_udp_drop++;
                                        handled = true;
                                    }
                                }
                            }
                        }

                        // 3. Classify for Workers if not handled
                        if (!handled) {
                            uint32_t target = get_target_worker((char*)b->m_IBuffer, b->m_Length, b->m_dwDeviceFlags, m_num_workers);
                            packet_worker_ids[ready_to_dispatch] = target;
                            packet_original_indices[ready_to_dispatch] = i;
                            worker_packet_counts[target]++;
                            ready_to_dispatch++;
                            m_stat_worker_dispatch++;
                        }
                    }

                    // 4. Batch Delivery
                    uint32_t worker_offsets[129]; worker_offsets[0] = 0;
                    for (unsigned int w = 0; w < m_num_workers; ++w) worker_offsets[w + 1] = worker_offsets[w] + worker_packet_counts[w];

                    PINTERMEDIATE_BUFFER sorted_bufs[BATCH_SIZE];
                    uint32_t sorted_idxs[BATCH_SIZE];
                    uint32_t current_pos[128]; memcpy(current_pos, worker_offsets, sizeof(uint32_t) * 128);

                    for (uint32_t i = 0; i < ready_to_dispatch; ++i) {
                        uint32_t target = packet_worker_ids[i];
                        uint32_t pos = current_pos[target]++;
                        sorted_bufs[pos] = m_read_request->EthPacket[packet_original_indices[i]].Buffer;
                        sorted_idxs[pos] = packet_original_indices[i];
                    }

                    for (unsigned int w = 0; w < m_num_workers; ++w) {
                        uint32_t count = worker_packet_counts[w];
                        if (count > 0) {
                            WorkerQueue* q = m_worker_queues[w].get();
                            size_t actual = q->push_batch(&sorted_bufs[worker_offsets[w]], count);
                            if (w < MAX_WORKERS && actual > 0) {
                                m_stat_worker_in_pkts[w].fetch_add(actual, std::memory_order_relaxed);
                            }
                            if (actual > 0) {
                                for (size_t j = 0; j < actual; ++j) m_read_request->EthPacket[sorted_idxs[worker_offsets[w] + j]].Buffer = nullptr;
                                q->cv.notify_one();
                            }
                            if (actual < count) m_stat_dropped_pkts += (count - actual);
                        }
                    }

                    // 5. Batch Refill
                    unsigned int refill_needed = 0;
                    for (unsigned int i = 0; i < BATCH_SIZE; ++i) {
                        if (m_read_request->EthPacket[i].Buffer == nullptr) refill_needed++;
                    }
                    if (refill_needed > 0) {
                        PINTERMEDIATE_BUFFER next_bufs[BATCH_SIZE];
                        size_t got = PacketPool::instance().acquire_batch(next_bufs, refill_needed);
                        unsigned int n = 0;
                        for (unsigned int i = 0; i < BATCH_SIZE && n < got; ++i) {
                            if (m_read_request->EthPacket[i].Buffer == nullptr) m_read_request->EthPacket[i].Buffer = next_bufs[n++];
                        }
                    }
                } else {
                    data_available = false;
                }
            } else {
                data_available = false;
            }
        }

        // 2. Stats
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_last_stat_time).count();
        if (elapsed_ms >= 1000) {
            uint64_t dl_pkts = m_stat_dl_pkts.exchange(0); uint64_t dl_bytes = m_stat_dl_bytes.exchange(0);
            uint64_t ul_pkts = m_stat_ul_pkts.exchange(0); uint64_t ul_bytes = m_stat_ul_bytes.exchange(0);
            uint64_t drops = m_stat_dropped_pkts.exchange(0);
            uint64_t work_us = m_stat_work_time_us.exchange(0);
            uint64_t arp_pass = m_stat_arp_pass.exchange(0);
            uint64_t eapol_pass = m_stat_eapol_pass.exchange(0);
            uint64_t ipv6_drop = m_stat_ipv6_drop.exchange(0);
            uint64_t dhcp_pass = m_stat_dhcp_pass.exchange(0);
            uint64_t dhcp_patch = m_stat_dhcp_patch.exchange(0);
            uint64_t lan_discovery_pass = m_stat_lan_discovery_pass.exchange(0);
            uint64_t pressure_udp_drop = m_stat_pressure_udp_drop.exchange(0);
            uint64_t ics_drop = m_stat_ics_drop.exchange(0);
            uint64_t icmp_reply = m_stat_icmp_reply.exchange(0);
            uint64_t worker_dispatch = m_stat_worker_dispatch.exchange(0);
            uint64_t send_adapter_fail = m_stat_send_adapter_fail.exchange(0);
            uint64_t send_stack_fail = m_stat_send_stack_fail.exchange(0);
            uint64_t batch_adapter_fail = m_stat_batch_adapter_fail.exchange(0);
            uint64_t batch_stack_fail = m_stat_batch_stack_fail.exchange(0);
            double dl_mbps = (dl_bytes * 8.0) / (elapsed_ms * 1000.0);
            double ul_mbps = (ul_bytes * 8.0) / (elapsed_ms * 1000.0);
            size_t backlog = 0;
            size_t max_worker_q = 0;
            size_t max_worker_id = 0;
            size_t active_worker_q = 0;
            struct WorkerSnapshot {
                unsigned int id;
                size_t q;
                uint64_t in;
                uint64_t out;
                uint64_t loops;
                uint32_t stage;
                uint64_t stage_age_ms;
                uint64_t seen_age_ms;
                uint32_t batch;
            };
            WorkerSnapshot all_workers[MAX_WORKERS] = {};
            WorkerSnapshot top[3] = {};
            uint64_t now_ms = GetTickCount64();
            for (auto& q : m_worker_queues) {
                backlog += q->size();
            }
            for (unsigned int w = 0; w < m_num_workers && w < MAX_WORKERS; ++w) {
                size_t qsize = m_worker_queues[w]->size();
                uint64_t in = m_stat_worker_in_pkts[w].exchange(0, std::memory_order_relaxed);
                uint64_t out = m_stat_worker_out_pkts[w].exchange(0, std::memory_order_relaxed);
                uint64_t loops = m_stat_worker_loops[w].exchange(0, std::memory_order_relaxed);
                uint32_t stage = m_stat_worker_stage[w].load(std::memory_order_relaxed);
                uint64_t stage_ms = m_stat_worker_stage_ms[w].load(std::memory_order_relaxed);
                uint64_t seen_ms = m_stat_worker_seen_ms[w].load(std::memory_order_relaxed);
                uint32_t batch = m_stat_worker_batch[w].load(std::memory_order_relaxed);
                uint64_t stage_age_ms = stage_ms > 0 && now_ms >= stage_ms ? now_ms - stage_ms : 0;
                uint64_t seen_age_ms = seen_ms > 0 && now_ms >= seen_ms ? now_ms - seen_ms : 0;
                if (qsize > 0) active_worker_q++;
                if (qsize > max_worker_q) {
                    max_worker_q = qsize;
                    max_worker_id = w;
                }
                WorkerSnapshot snap{ w, qsize, in, out, loops, stage, stage_age_ms, seen_age_ms, batch };
                all_workers[w] = snap;
                for (int ti = 0; ti < 3; ++ti) {
                    if (snap.q > top[ti].q) {
                        for (int sj = 2; sj > ti; --sj) top[sj] = top[sj - 1];
                        top[ti] = snap;
                        break;
                    }
                }
            }
            uint64_t total_pkts = dl_pkts + ul_pkts;
            LOG_DEBUG("[Perf] DL: %.2f Mbps (%llu p) | UL: %.2f Mbps (%llu p) | Drops: %llu | Backlog: %zu | AvgWork: %llu us",
                dl_mbps, dl_pkts, ul_mbps, ul_pkts, drops, backlog, total_pkts > 0 ? work_us / total_pkts : 0);
            LOG_WARN("[PKTSTAT] dl_pkts=%llu ul_pkts=%llu dl_mbps=%.2f ul_mbps=%.2f worker=%llu drops=%llu backlog=%zu arp_pass=%llu eapol_pass=%llu ipv6_drop=%llu dhcp_pass=%llu dhcp_patch=%llu lan_discovery_pass=%llu pressure_udp_drop=%llu ics_drop=%llu icmp_reply=%llu send_adapter_fail=%llu send_stack_fail=%llu batch_adapter_fail=%llu batch_stack_fail=%llu",
                dl_pkts, ul_pkts, dl_mbps, ul_mbps, worker_dispatch, drops, backlog,
                arp_pass, eapol_pass, ipv6_drop, dhcp_pass, dhcp_patch, lan_discovery_pass,
                pressure_udp_drop, ics_drop, icmp_reply, send_adapter_fail, send_stack_fail,
                batch_adapter_fail, batch_stack_fail);
            LOG_WARN("[WORKERSTAT] workers=%u backlog=%zu active_q=%zu max_q=%zu max_worker=%zu avg_q=%.1f top=%u:q%zu/in%llu/out%llu/loop%llu,%u:q%zu/in%llu/out%llu/loop%llu,%u:q%zu/in%llu/out%llu/loop%llu",
                m_num_workers,
                backlog,
                active_worker_q,
                max_worker_q,
                max_worker_id,
                m_num_workers ? (double)backlog / (double)m_num_workers : 0.0,
                top[0].id, top[0].q, (unsigned long long)top[0].in, (unsigned long long)top[0].out, (unsigned long long)top[0].loops,
                top[1].id, top[1].q, (unsigned long long)top[1].in, (unsigned long long)top[1].out, (unsigned long long)top[1].loops,
                top[2].id, top[2].q, (unsigned long long)top[2].in, (unsigned long long)top[2].out, (unsigned long long)top[2].loops);
            char worker_all[2048] = {};
            char worker_heart[2048] = {};
            size_t all_pos = 0;
            size_t heart_pos = 0;
            for (unsigned int w = 0; w < m_num_workers && w < MAX_WORKERS; ++w) {
                const WorkerSnapshot& s = all_workers[w];
                int n = sprintf_s(worker_all + all_pos, sizeof(worker_all) - all_pos,
                    "%s%u:q%zu/in%llu/out%llu/loop%llu",
                    w == 0 ? "" : ";",
                    s.id,
                    s.q,
                    (unsigned long long)s.in,
                    (unsigned long long)s.out,
                    (unsigned long long)s.loops);
                if (n > 0) all_pos += (size_t)n;

                n = sprintf_s(worker_heart + heart_pos, sizeof(worker_heart) - heart_pos,
                    "%s%u:%s/age%llums/seen%llums/b%u",
                    w == 0 ? "" : ";",
                    s.id,
                    worker_stage_name(s.stage),
                    (unsigned long long)s.stage_age_ms,
                    (unsigned long long)s.seen_age_ms,
                    s.batch);
                if (n > 0) heart_pos += (size_t)n;
            }
            LOG_WARN("[WORKERALL] %s", worker_all);
            LOG_WARN("[WORKERHEART] %s", worker_heart);
            m_last_stat_time = now;
        }
    }
}

bool WinPkFilterDriver::get_adapter_mac(const std::string& adapter_name, uint8_t* mac) {
    PIP_ADAPTER_ADDRESSES pAddrs = (PIP_ADAPTER_ADDRESSES)malloc(15000); ULONG len = 15000;
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, pAddrs, &len) == ERROR_SUCCESS) {
        for (auto p = pAddrs; p; p = p->Next) if (adapter_name.find(p->AdapterName) != std::string::npos) { memcpy(mac, p->PhysicalAddress, 6); free(pAddrs); return true; }
    }
    free(pAddrs); return false;
}

bool WinPkFilterDriver::send_to_adapter(const char* packet, size_t length) {
    std::lock_guard<std::mutex> lock(m_send_mutex);
    size_t clen = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(m_send_buffer->m_IBuffer, packet, clen); m_send_buffer->m_Length = (ULONG)clen; m_send_buffer->m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    ETH_REQUEST req = { m_adapter_handle, { m_send_buffer } };
    bool ok = m_ndis_api.SendPacketToAdapter(&req) != FALSE;
    if (!ok) m_stat_send_adapter_fail++;
    return ok;
}

bool WinPkFilterDriver::send_to_mstcp(const char* packet, size_t length) {
    std::lock_guard<std::mutex> lock(m_send_mutex);
    size_t clen = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(m_send_buffer->m_IBuffer, packet, clen); m_send_buffer->m_Length = (ULONG)clen; m_send_buffer->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    ETH_REQUEST req = { m_adapter_handle, { m_send_buffer } };
    bool ok = m_ndis_api.SendPacketToMstcp(&req) != FALSE;
    if (!ok) m_stat_send_stack_fail++;
    return ok;
}

void WinPkFilterDriver::send_ipv6_tcp_rst(const char* packet, size_t length) {
    if (length < 14 + sizeof(IPV6_HEADER) + sizeof(TCP_HEADER)) return;

    // Use a local buffer for the RST packet
    uint8_t rst_frame[14 + sizeof(IPV6_HEADER) + sizeof(TCP_HEADER)];

    // Original headers
    const uint8_t* eth_orig = (const uint8_t*)packet;
    PIPV6_HEADER ipv6_orig = (PIPV6_HEADER)(packet + 14);
    PTCP_HEADER tcp_orig = (PTCP_HEADER)(packet + 14 + sizeof(IPV6_HEADER));

    if (ipv6_orig->NextHeader != IPPROTO_TCP) return;

    // Ethernet Header
    memcpy(rst_frame, eth_orig + 6, 6);        // Dst = Original Src
    memcpy(rst_frame + 6, eth_orig, 6);        // Src = Original Dst
    *(USHORT*)(rst_frame + 12) = htons(ETHERTYPE_IPV6);

    // IPv6 Header
    PIPV6_HEADER ipv6 = (PIPV6_HEADER)(rst_frame + 14);
    ipv6->Ver_Traffic_Flow = ipv6_orig->Ver_Traffic_Flow; // Copy version/traffic class/flow label
    ipv6->PayloadLen = htons(sizeof(TCP_HEADER));
    ipv6->NextHeader = IPPROTO_TCP;
    ipv6->HopLimit = 64;
    memcpy(ipv6->SrcAddr, ipv6_orig->DstAddr, 16);
    memcpy(ipv6->DstAddr, ipv6_orig->SrcAddr, 16);

    // TCP Header
    PTCP_HEADER tcp = (PTCP_HEADER)(rst_frame + 14 + sizeof(IPV6_HEADER));
    memset(tcp, 0, sizeof(TCP_HEADER));
    tcp->SrcPort = tcp_orig->DstPort;
    tcp->DstPort = tcp_orig->SrcPort;

    // RST Logic
    if (tcp_orig->Flags & 0x02) { // SYN
        tcp->SeqNum = 0;
        tcp->AckNum = htonl(ntohl(tcp_orig->SeqNum) + 1);
        tcp->Flags = 0x14; // RST | ACK
    }
    else {
        tcp->SeqNum = tcp_orig->AckNum;
        tcp->AckNum = 0;
        tcp->Flags = 0x04; // RST
    }

    tcp->HdrLen = (sizeof(TCP_HEADER) / 4) << 4;
    tcp->WinSize = 0;
    tcp->Csum = 0;

    // TCP Checksum calculation
    TCPV6_PSD_HEADER psd;
    memcpy(psd.SrcAddr, ipv6->SrcAddr, 16);
    memcpy(psd.DstAddr, ipv6->DstAddr, 16);
    psd.PayloadLen = htonl(sizeof(TCP_HEADER));
    memset(psd.Zero, 0, sizeof(psd.Zero));
    psd.NextHeader = IPPROTO_TCP;

    uint32_t sum = csum_partial(&psd, sizeof(psd), 0);
    tcp->Csum = csum_finalize(csum_partial(tcp, sizeof(TCP_HEADER), sum));

    // Send back to the client
    this->send_to_adapter((const char*)rst_frame, sizeof(rst_frame));
}

void  WinPkFilterDriver::send_dhcp_response(const uint8_t* client_mac, const uint32_t src_ip, const DhcpResponse& dhcp_r, const uint8_t* m_adapter_mac) {
    if (dhcp_r.length == 0 || dhcp_r.data.empty()) return;

    // 计算总长度
    size_t frame_len = 14 + 20 + 8 + dhcp_r.length; // ETH + IP + UDP + DHCP
    std::vector<uint8_t> frame(frame_len);

    uint8_t* ptr = frame.data();

    // --- 以太网头 ---
    memcpy(ptr, client_mac, 6);           // 目标 MAC = 客户端
    memcpy(ptr + 6, m_adapter_mac, 6);    // 源 MAC = 虚拟网卡
    ptr[12] = 0x08; ptr[13] = 0x00;       // EtherType = IPv4
    ptr += 14;

    // --- IP 头 ---
    uint16_t total_len = htons(20 + 8 + dhcp_r.length); // IP头20 + UDP头8 + DHCP payload
    ptr[0] = 0x45;       // Version 4, IHL=5
    ptr[1] = 0x00;       // TOS
    memcpy(ptr + 2, &total_len, 2);
    ptr[4] = ptr[5] = ptr[6] = ptr[7] = 0x00; // ID + Flags/FragOffset
    ptr[8] = 64;         // TTL
    ptr[9] = 17;         // Protocol = UDP
    ptr[10] = ptr[11] = 0x00; // Checksum 先填0

    // Source IP
    uint32_t sip = htonl(src_ip);
    memcpy(ptr + 12, &sip, 4);

    // Dest IP = 广播
    uint32_t dip = htonl(0xFFFFFFFF);
    memcpy(ptr + 16, &dip, 4);

    // 计算 IP 校验和
    auto calc_ip_checksum = [](uint8_t* hdr) -> uint16_t {
        uint32_t sum = 0;
        for (int i = 0; i < 20; i += 2) {
            sum += (hdr[i] << 8) | hdr[i + 1];
        }
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        return (uint16_t)(~sum);
        };
    uint16_t ip_cksum = calc_ip_checksum(ptr);
    memcpy(ptr + 10, &ip_cksum, 2);
    ptr += 20;

    // --- UDP 头 ---
    uint16_t src_port = htons(67);
    uint16_t dst_port = htons(68);
    uint16_t udp_len = htons(8 + dhcp_r.length);
    memcpy(ptr, &src_port, 2);
    memcpy(ptr + 2, &dst_port, 2);
    memcpy(ptr + 4, &udp_len, 2);
    ptr[6] = ptr[7] = 0x00; // UDP checksum可填0
    ptr += 8;

    // --- DHCP payload ---
    memcpy(ptr, dhcp_r.data.data(), dhcp_r.length);

    // --- 发送 ---
    this->send_to_adapter((const char*)frame.data(), frame.size());
}

void WinPkFilterDriver::send_icmp_port_unreachable(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    if (m_adapter_handle == NULL) return;

    // ICMP Destination Unreachable packet:
    // [Ethernet] [IP Header] [ICMP Header] [Original IP Header] [Original UDP Header (8 bytes)]
    
    const size_t ip_len = 20;
    const size_t icmp_len = 8; 
    const size_t original_payload_len = 20 + 8; // Original IP + 8 bytes of UDP
    const size_t total_payload_len = icmp_len + original_payload_len;
    const size_t total_packet_size = 14 + ip_len + total_payload_len; 

    uint8_t packet[256];
    if (total_packet_size > sizeof(packet)) return;
    memset(packet, 0, total_packet_size);

    // 1. Ethernet Header
    // Use DHCP cache to get the client MAC address (most efficient)
    if (g_dhcp_server_ptr && g_dhcp_server_ptr->get_mac_by_ip(src_ip, packet)) {
        // MAC already copied into packet[0..5]
    } else {
        memset(packet, 0xFF, 6); // Fallback to broadcast
    }
    memcpy(packet + 6, m_adapter_mac, 6); 
    packet[12] = 0x08; packet[13] = 0x00; // IPv4

    // 2. IP Header
    uint8_t* ip_ptr = packet + 14;
    ip_ptr[0] = 0x45;
    ip_ptr[1] = 0x00;
    uint16_t total_len_val = (uint16_t)(ip_len + total_payload_len);
    uint16_t total_len_net = htons(total_len_val);
    memcpy(ip_ptr + 2, &total_len_net, 2);
    ip_ptr[8] = 128; // TTL
    ip_ptr[9] = 1;   // Protocol = ICMP
    
    // IP addresses for ICMP reply
    // src_ip/port are client's
    // dst_ip/port are original target's
    memcpy(ip_ptr + 12, &dst_ip, 4); // Source of ICMP = Original Dst IP
    memcpy(ip_ptr + 16, &src_ip, 4); // Destination of ICMP = Original Src IP

    // 3. ICMP Header
    uint8_t* icmp_ptr = packet + 14 + ip_len;
    icmp_ptr[0] = 3; // Type: Destination Unreachable
    icmp_ptr[1] = 3; // Code: Port Unreachable

    // 4. Original Packet snippet (IP Header + 8 bytes of UDP)
    uint8_t* orig_ip_ptr = icmp_ptr + 8;
    orig_ip_ptr[0] = 0x45;
    orig_ip_ptr[9] = 17; // UDP
    memcpy(orig_ip_ptr + 12, &src_ip, 4);
    memcpy(orig_ip_ptr + 16, &dst_ip, 4);
    
    uint16_t* orig_udp = (uint16_t*)(orig_ip_ptr + 20);
    orig_udp[0] = src_port;
    orig_udp[1] = dst_port;

    // 5. Calculate Checksums
    auto calc_checksum = [](uint8_t* hdr, int len) -> uint16_t {
        uint32_t sum = 0;
        for (int i = 0; i < len; i += 2) {
            sum += (hdr[i] << 8) | hdr[i + 1];
        }
        if (len % 2) sum += (hdr[len - 1] << 8);
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        return (uint16_t)(~sum);
    };

    uint16_t ip_cksum = htons(calc_checksum(ip_ptr, 20));
    memcpy(ip_ptr + 10, &ip_cksum, 2);

    uint16_t icmp_cksum = htons(calc_checksum(icmp_ptr, (int)total_payload_len));
    memcpy(icmp_ptr + 2, &icmp_cksum, 2);

    // 6. Send to Adapter
    this->send_to_adapter((const char*)packet, total_packet_size);
}
