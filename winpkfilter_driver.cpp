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

WinPkFilterDriver::WinPkFilterDriver()
    : m_adapter_handle(nullptr), m_wait_event(nullptr), m_running(false), m_gateway_ip(0) {
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

bool WinPkFilterDriver::start_batch(const std::string& adapter_name, BatchPacketHandler handler) {
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
    m_gateway_ip = inet_addr(g_config.gateway_ip.c_str());
    get_adapter_mac(adapter_name, m_adapter_mac);
    m_batch_handler = handler;
    m_wait_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    m_ndis_api.SetPacketEvent(m_adapter_handle, m_wait_event);
    ADAPTER_MODE mode = { m_adapter_handle,  MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL };
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

    auto flush_packets = [&](PETH_M_REQUEST req, bool to_adapter) {
        if (req->dwPacketsNumber > 0) {
            if (to_adapter) m_ndis_api.SendPacketsToAdapter(req);
            else m_ndis_api.SendPacketsToMstcp(req);

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
        // Wait for packets if queue is empty
        {
            std::unique_lock<std::mutex> lock(m_worker_queues[worker_id]->mtx);
            m_worker_queues[worker_id]->cv.wait(lock, [&] {
                return !m_running || (m_worker_queues[worker_id]->head.load(std::memory_order_relaxed) != m_worker_queues[worker_id]->tail.load(std::memory_order_relaxed));
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

                                        ip->SrcAddr = key4->dst_ip;
                                        udp->SrcPort = key4->dst_port;
                                        udp->DstPort = key4->src_port;

                                        incremental_checksum_update(&ip->Csum, old_src_ip, ip->SrcAddr);
                                        incremental_checksum_update(&udp->Csum, old_src_ip, ip->SrcAddr);
                                        incremental_checksum_update(&udp->Csum, old_src_port, udp->SrcPort);
                                        incremental_checksum_update(&udp->Csum, old_dst_port, udp->DstPort);
                                    }
                                    else {
                                        recalculate_ip_checksum(ip); recalculate_tcp_udp_checksum(ip);
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
                        if (to_adapter_req->dwPacketsNumber >= BATCH_SIZE) flush_packets(to_adapter_req, true);
                    }
                    else {
                        to_stack_req->EthPacket[to_stack_req->dwPacketsNumber++].Buffer = b_raw;
                        if (to_stack_req->dwPacketsNumber >= BATCH_SIZE) flush_packets(to_stack_req, false);
                    }
                }
            }
        }

        // Flush remaining packets after the queue has been fully drained
        flush_packets(to_adapter_req, true);
        flush_packets(to_stack_req, false);

        m_stat_work_time_us += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time).count();
    }
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
                    bool worker_notified[128] = { false }; // Keep track of which workers to wake

                    for (unsigned int i = 0; i < m_read_request->dwPacketsSuccess; ++i) {
                        PINTERMEDIATE_BUFFER b = m_read_request->EthPacket[i].Buffer;
                        if (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) { // Outbound from local stack (Upload)
                            m_stat_ul_pkts++; m_stat_ul_bytes += b->m_Length;
                        }
                        else { // Inbound from network (Download)
                            m_stat_dl_pkts++; m_stat_dl_bytes += b->m_Length;
                        }

                        // --- Fast Path ---
                        bool handled = false;
                        if (b->m_Length >= 14) {
                            unsigned char* buffer = b->m_IBuffer;
                            USHORT ether_type = ntohs(*(USHORT*)(buffer + 12));

                            if (ether_type != ETHERTYPE_IP) {
                                if (ether_type == ETHERTYPE_IPV6) {
                                    if (b->m_dwDeviceFlags != PACKET_FLAG_ON_SEND && b->m_Length >= 14 + sizeof(IPV6_HEADER) + sizeof(TCP_HEADER)) {
                                        PIPV6_HEADER ipv6 = (PIPV6_HEADER)(buffer + 14);
                                        if (ipv6->NextHeader == IPPROTO_TCP) {
                                            PTCP_HEADER tcp = (PTCP_HEADER)(buffer + 14 + sizeof(IPV6_HEADER));
                                            if (tcp->Flags & 0x02) this->send_ipv6_tcp_rst((const char*)buffer, b->m_Length);
                                        }
                                    }
                                    handled = true; // Dropped (buffer reused)
                                }
                                else if (ether_type == ETHERTYPE_ARP && b->m_Length >= 14 + sizeof(ARP_HEADER)) {
                                    PARP_HEADER arp = (PARP_HEADER)(buffer + 14);
                                    if (ntohs(arp->OpCode) == 1 && arp->DstIp == m_gateway_ip && b->m_dwDeviceFlags != PACKET_FLAG_ON_SEND) {
                                        memcpy(buffer, buffer + 6, 6);
                                        memcpy(buffer + 6, m_adapter_mac, 6);
                                        arp->OpCode = htons(2);
                                        memcpy(arp->DstMac, arp->SrcMac, 6);
                                        arp->DstIp = arp->SrcIp;
                                        memcpy(arp->SrcMac, m_adapter_mac, 6);
                                        arp->SrcIp = m_gateway_ip;
                                        this->send_to_adapter((const char*)buffer, b->m_Length);
                                        handled = true; // Buffer reused
                                    }
                                }
                                else if (ether_type == 0x888E) { // EAPOL
                                    if (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) this->send_to_adapter((const char*)buffer, b->m_Length);
                                    else this->send_to_mstcp((const char*)buffer, b->m_Length);
                                    handled = true;
                                }
                            }
                            else if (b->m_Length >= 34) {
                                PIP_HEADER ip = (PIP_HEADER)(buffer + 14);
                                if (ip->SrcAddr == 0x0189A8C0) handled = true; // Block ICS
                                else if (ip->Proto == IPPROTO_ICMP && b->m_dwDeviceFlags != PACKET_FLAG_ON_SEND && b->m_Length >= 14 + ((ip->Ver_HLen & 0x0F) * 4) + sizeof(ICMP_HEADER)) {
                                    PICMP_HEADER icmp = (PICMP_HEADER)(buffer + 14 + ((ip->Ver_HLen & 0x0F) * 4));
                                    if (icmp->Type == 8) {
                                        uint8_t tmac[6]; memcpy(tmac, buffer, 6); memcpy(buffer, buffer + 6, 6); memcpy(buffer + 6, tmac, 6);
                                        ULONG tip = ip->SrcAddr; ip->SrcAddr = ip->DstAddr; ip->DstAddr = tip; icmp->Type = 0;
                                        recalculate_ip_checksum(ip); recalculate_tcp_udp_checksum(ip);
                                        this->send_to_adapter((const char*)buffer, b->m_Length);
                                        handled = true;
                                    }
                                }
                                else if (ip->Proto == IPPROTO_UDP) {
                                    PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + ((ip->Ver_HLen & 0x0F) * 4));
                                    USHORT sp = ntohs(udp->SrcPort), dp = ntohs(udp->DstPort);
                                    if (sp == 67 || dp == 67 || sp == 68 || dp == 68) {
                                        DhcpResponse dhcp_r = g_dhcp_server_ptr->handle_request_buffer((const char*)udp + sizeof(UDP_HEADER), b->m_Length);
                                        if (dhcp_r.length > 0) this->send_dhcp_response(((uint8_t*)ip) - 8, m_gateway_ip, dhcp_r, m_adapter_mac);
                                        handled = true;
                                    }
                                    else if (sp == 1900 || dp == 1900 || sp == 5353 || dp == 5353 || sp == 137 || dp == 137 || sp == 138 || dp == 138) handled = true;
                                }
                            }
                        }

                        if (!handled) {
                            uint32_t target = get_target_worker((char*)b->m_IBuffer, b->m_Length, b->m_dwDeviceFlags, m_num_workers);
                            if (m_worker_queues[target]->push(b)) {
                                m_read_request->EthPacket[i].Buffer = nullptr; // Transferred
                                worker_notified[target] = true;
                            }
                            else {
                                // Queue full, reused in-place (packet dropped)
                                m_stat_dropped_pkts++;
                            }
                        }
                    }

                    // Batch Refill
                    unsigned int refill_needed = 0;
                    for (unsigned int i = 0; i < m_read_request->dwPacketsSuccess; ++i) {
                        if (m_read_request->EthPacket[i].Buffer == nullptr) refill_needed++;
                    }
                    if (refill_needed > 0) {
                        PINTERMEDIATE_BUFFER next_bufs[BATCH_SIZE];
                        size_t got = PacketPool::instance().acquire_batch(next_bufs, refill_needed);
                        unsigned int n = 0;
                        for (unsigned int i = 0; i < m_read_request->dwPacketsSuccess && n < got; ++i) {
                            if (m_read_request->EthPacket[i].Buffer == nullptr) m_read_request->EthPacket[i].Buffer = next_bufs[n++];
                        }
                    }

                    for (unsigned int i = 0; i < m_num_workers; ++i) {
                        if (worker_notified[i]) m_worker_queues[i]->cv.notify_one();
                    }
                }
                else {
                    data_available = false;
                }
            }
            else {
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
            double dl_mbps = (dl_bytes * 8.0) / (elapsed_ms * 1000.0);
            double ul_mbps = (ul_bytes * 8.0) / (elapsed_ms * 1000.0);
            size_t backlog = 0;
            for (auto& q : m_worker_queues) {
                backlog += q->size();
            }
            uint64_t total_pkts = dl_pkts + ul_pkts;
            LOG_DEBUG("[Perf] DL: %.2f Mbps (%llu p) | UL: %.2f Mbps (%llu p) | Drops: %llu | Backlog: %zu | AvgWork: %llu us",
                dl_mbps, dl_pkts, ul_mbps, ul_pkts, drops, backlog, total_pkts > 0 ? work_us / total_pkts : 0);
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
    return m_ndis_api.SendPacketToAdapter(&req) != FALSE;
}

bool WinPkFilterDriver::send_to_mstcp(const char* packet, size_t length) {
    std::lock_guard<std::mutex> lock(m_send_mutex);
    size_t clen = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(m_send_buffer->m_IBuffer, packet, clen); m_send_buffer->m_Length = (ULONG)clen; m_send_buffer->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    ETH_REQUEST req = { m_adapter_handle, { m_send_buffer } };
    return m_ndis_api.SendPacketToMstcp(&req) != FALSE;
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
