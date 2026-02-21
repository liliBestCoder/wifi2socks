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

#include <poppack.h>

const USHORT ETHERTYPE_IP = 0x0800;
const USHORT ETHERTYPE_ARP = 0x0806;
const USHORT NAT_TARGET_PORT = 3080;

#pragma comment(lib, "ndisapilib.lib")
#pragma comment(lib, "iphlpapi.lib")

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
    uint32_t sum = (~(*checksum)) & 0xFFFF;
    sum += (~old_val) & 0xFFFF;
    sum += new_val;
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    *checksum = ~((uint16_t)sum);
}

// 增量更新32位字段的校验和
static void incremental_checksum_update(uint16_t* checksum, uint32_t old_val, uint32_t new_val) {
    uint32_t sum = (~(*checksum)) & 0xFFFF;
    sum += (~(old_val & 0xFFFF)) & 0xFFFF;
    sum += (~(old_val >> 16)) & 0xFFFF;
    sum += (new_val & 0xFFFF);
    sum += (new_val >> 16);
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    *checksum = ~((uint16_t)sum);
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

// Smart worker dispatch: Check NAT mapping first, fallback to stable hash
static uint32_t get_target_worker(const char* packet, size_t length, uint32_t device_flags, uint32_t num_workers) {
    if (length < 14) return 0;
    
    USHORT ether_type = ntohs(*(USHORT*)(packet + 12));
    if (ether_type != ETHERTYPE_IP) {
        // Non-IP packets (ARP, IPv6, EAPOL, etc.)
        // Strategy: Hash the "Client" MAC to keep the session pinned to one worker.
        // ON_SEND (Stack->Adapter): Destination is Client (Offset 0).
        // ON_RECEIVE (Adapter->Stack): Source is Client (Offset 6).
        const uint8_t* mac;
        if (device_flags == PACKET_FLAG_ON_SEND) {
             mac = (const uint8_t*)(packet + 0); // Dst MAC
        } else {
             mac = (const uint8_t*)(packet + 6); // Src MAC
        }
        uint32_t hash = mac[0] ^ mac[1] ^ mac[2] ^ mac[3] ^ mac[4] ^ mac[5];
        return hash % num_workers;
    }

    if (length < 14 + sizeof(IP_HEADER)) return 0;
    PIP_HEADER ip = (PIP_HEADER)(packet + 14);

    uint32_t stable_ip;
    uint16_t stable_port = 0;
    bool valid_l4 = false;

    int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;

    // Strategy: Always anchor to "Client" side (Stable Side)
    // ON_SEND (Stack->Adapter): Use Destination (Remote/Client).
    // ON_RECEIVE (Adapter->Stack): Use Source (Remote/Client).
    if (device_flags == PACKET_FLAG_ON_SEND) {
        stable_ip = ip->DstAddr;
        if (ip->Proto == IPPROTO_TCP && length >= 14 + ip_hdr_len + sizeof(TCP_HEADER)) {
            stable_port = ((PTCP_HEADER)((char*)ip + ip_hdr_len))->DstPort;
            valid_l4 = true;
        } else if (ip->Proto == IPPROTO_UDP && length >= 14 + ip_hdr_len + sizeof(UDP_HEADER)) {
            stable_port = ((PUDP_HEADER)((char*)ip + ip_hdr_len))->DstPort;
            valid_l4 = true;
        }
    } else {
        stable_ip = ip->SrcAddr;
        if (ip->Proto == IPPROTO_TCP && length >= 14 + ip_hdr_len + sizeof(TCP_HEADER)) {
            stable_port = ((PTCP_HEADER)((char*)ip + ip_hdr_len))->SrcPort;
            valid_l4 = true;
        } else if (ip->Proto == IPPROTO_UDP && length >= 14 + ip_hdr_len + sizeof(UDP_HEADER)) {
            stable_port = ((PUDP_HEADER)((char*)ip + ip_hdr_len))->SrcPort;
            valid_l4 = true;
        }
    }

    if (valid_l4) {
        // 1. Try Lookup
        uint64_t key = NatManager::make_key(stable_ip, stable_port);
        auto mapping = NatManager::instance().get_mapping(key);
        if (mapping) {
            return mapping->worker_id; // Found established flow
        }

        // 2. Fallback: Consistent Hash (for new flows)
        // Combine IP, Port and Protocol. Avoid XOR-only zeros.
        // Mix bits to ensure good distribution.
        uint32_t hash = stable_ip ^ ((uint32_t)stable_port << 16) ^ stable_port ^ ip->Proto;
        return hash % num_workers;
    }

    return 0; // Default to worker 0 for non-IP/non-L4
}

WinPkFilterDriver::WinPkFilterDriver()
    : m_adapter_handle(nullptr), m_wait_event(nullptr), m_running(false), m_gateway_ip(0), m_results_event(nullptr) {
    CNdisApi::SetPoolSize(32768);

    m_num_workers = (std::max)(1u, std::thread::hardware_concurrency());
    for (unsigned int i = 0; i < m_num_workers; ++i) {
        m_worker_queues.push_back(std::make_unique<WorkerQueue>());
    }
    m_results_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    m_read_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    for (int i = 0; i < BATCH_SIZE; ++i) m_read_buffers[i] = nullptr;
    m_write_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    m_mstcp_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    m_send_buffer = new INTERMEDIATE_BUFFER();
    memset(m_adapter_mac, 0, 6);
    m_last_stat_time = std::chrono::steady_clock::now();
}

WinPkFilterDriver::~WinPkFilterDriver() {
    stop();
    if (m_results_event) CloseHandle(m_results_event);
    for (int i = 0; i < BATCH_SIZE; ++i) if (m_read_buffers[i]) PacketPool::instance().release(m_read_buffers[i]);
    free(m_read_request); free(m_write_request); free(m_mstcp_request); delete m_send_buffer;
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
    m_gateway_ip = inet_addr(g_config.tap_ip.c_str());
    get_adapter_mac(adapter_name, m_adapter_mac);
    m_batch_handler = handler;
    m_wait_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    m_ndis_api.SetPacketEvent(m_adapter_handle, m_wait_event);
    ADAPTER_MODE mode = { m_adapter_handle, MSTCP_FLAG_SENT_RECEIVE | MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL };
    m_ndis_api.SetAdapterMode(&mode);
    m_running = true;
    m_read_request->hAdapterHandle = m_adapter_handle;

    m_reader_thread = std::thread(&WinPkFilterDriver::run, this);
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
    if (m_results_event) SetEvent(m_results_event);
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
    std::list<QueuedPacket> local_queue;
    std::vector<Packet> packets_to_send; packets_to_send.reserve(BATCH_SIZE);
    std::vector<Packet> packets_to_mstcp; packets_to_mstcp.reserve(BATCH_SIZE);
    while (m_running) {
        {
            std::unique_lock<std::mutex> lock(m_worker_queues[worker_id]->mtx);
            m_worker_queues[worker_id]->cv.wait(lock, [&] { return !m_running || !m_worker_queues[worker_id]->packets.empty(); });
            if (!m_running && m_worker_queues[worker_id]->packets.empty()) break;
            local_queue.splice(local_queue.end(), m_worker_queues[worker_id]->packets);
        }

        auto start_time = std::chrono::steady_clock::now();
        packets_to_send.clear(); packets_to_mstcp.clear();

        for (auto& p_in : local_queue) {
            Packet p{ RawPacketPtr(p_in.buffer), (p_in.buffer->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) };
            unsigned char* buffer = p.data->m_IBuffer;
            size_t length = p.data->m_Length;
            bool handled = false;

            if (length >= 14) {
                USHORT ether_type = ntohs(*(USHORT*)(buffer + 12));
                if (ether_type == ETHERTYPE_IP && length >= 34) {
                    PIP_HEADER ip = (PIP_HEADER)(buffer + 14);

                    if (!handled) {
                        bool should_intercept = false;
                        if (!p.outbound && (ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP) && ip->SrcAddr != m_gateway_ip) {
                            should_intercept = true;
                            // Check if packet is destined to the Proxy Port on the Gateway (Explicit Proxy or RST)
                            // We should NOT intercept these, to avoid Poisoning/Looping, and to let them hit the socket directly.
                            if (ip->DstAddr == m_gateway_ip) {
                                int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;
                                USHORT dport = (ip->Proto == IPPROTO_TCP) ? ((PTCP_HEADER)((char*)ip + ip_hdr_len))->DstPort : ((PUDP_HEADER)((char*)ip + ip_hdr_len))->DstPort;
                                if (dport == htons(NAT_TARGET_PORT)) {
                                    should_intercept = false;
                                    recalculate_ip_checksum(ip);
                                    recalculate_tcp_udp_checksum(ip);
                                }
                            }
                        }

                        if (should_intercept) {
                            OriginalDestination od(ip->DstAddr, (ip->Proto == IPPROTO_TCP) ? ((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort : ((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort, ip->SrcAddr);
                            uint64_t key = NatManager::make_key(ip->SrcAddr, (ip->Proto == IPPROTO_TCP) ? ((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->SrcPort : ((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->SrcPort);
                            uint32_t old_dst_ip = ip->DstAddr;
                            if (ip->Proto == IPPROTO_TCP) {
                                PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                uint16_t old_dst_port = tcp->DstPort;
                                od.port = tcp->DstPort; NatManager::instance().create_tcp_mapping(key, od, worker_id);
                                ip->DstAddr = m_gateway_ip;
                                tcp->DstPort = htons(NAT_TARGET_PORT);
                                incremental_checksum_update(&ip->Csum, old_dst_ip, ip->DstAddr);
                                incremental_checksum_update(&tcp->Csum, old_dst_ip, ip->DstAddr);
                                incremental_checksum_update(&tcp->Csum, old_dst_port, tcp->DstPort);
                            }
                            else {
                                PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                uint16_t old_dst_port = udp->DstPort;
                                od.port = udp->DstPort; NatManager::instance().create_or_update_udp_mapping(key, od, worker_id);
                                ip->DstAddr = m_gateway_ip;
                                udp->DstPort = htons(NAT_TARGET_PORT);
                                incremental_checksum_update(&ip->Csum, old_dst_ip, ip->DstAddr);
                                incremental_checksum_update(&udp->Csum, old_dst_ip, ip->DstAddr);
                                incremental_checksum_update(&udp->Csum, old_dst_port, udp->DstPort);
                            }
                            packets_to_mstcp.push_back(std::move(p)); handled = true;
                        }
                        else if (p.outbound && (ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP)) {
                            USHORT sport = (ip->Proto == IPPROTO_TCP) ? ntohs(((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->SrcPort) : ntohs(((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->SrcPort);
                            if (sport == NAT_TARGET_PORT) {
                                auto od = NatManager::instance().get_mapping(NatManager::make_key(ip->DstAddr, (ip->Proto == IPPROTO_TCP) ? ((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort : ((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort));
                                if (od) {
                                    // Mapping found, packet is modified.
                                    // FORCE RECALCULATION: NDIS Checksum Offload might leave Csum as 0.
                                    // Incremental update on 0 results in an invalid checksum.
                                    ip->SrcAddr = od->ip;
                                    
                                    if (ip->Proto == IPPROTO_TCP) {
                                        PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                        tcp->SrcPort = od->port;
                                    }
                                    else { // UDP
                                        PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                        udp->SrcPort = od->port;
                                    }
                                    recalculate_ip_checksum(ip);
                                    recalculate_tcp_udp_checksum(ip);
                                }
                                else {
                                    // No mapping found. Packet is not modified, but we still recalculate checksums
                                    // because capturing the packet breaks NDIS Checksum Offload context.
                                    recalculate_ip_checksum(ip);
                                    recalculate_tcp_udp_checksum(ip);
                                }
                            }
                            packets_to_send.push_back(std::move(p)); handled = true;
                        }
                    }
                }
            }
            if (!handled) p.outbound ? packets_to_send.push_back(std::move(p)) : packets_to_mstcp.push_back(std::move(p));
        }

        m_stat_work_time_us += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time).count();
        local_queue.clear();
        if (!packets_to_send.empty() || !packets_to_mstcp.empty()) {
            std::lock_guard<std::mutex> lock(m_results_queue.mtx);
            for (auto& pkt : packets_to_send) m_results_queue.packets.push_back({ pkt.data.release(), PacketDestination::TO_ADAPTER });
            for (auto& pkt : packets_to_mstcp) m_results_queue.packets.push_back({ pkt.data.release(), PacketDestination::TO_MSTCP });
            SetEvent(m_results_event);
        }
    }
}

void WinPkFilterDriver::run() {
    std::list<ProcessedPacket> local_results;
    HANDLE wait_events[2] = { m_wait_event, m_results_event };
    while (m_running) {
        WaitForMultipleObjects(2, wait_events, FALSE, 10);
        if (!m_running) break;

        // 1. Read & Dispatch
        for (int r = 0; r < 20 && m_running; ++r) {
            m_read_request->dwPacketsNumber = BATCH_SIZE;
            if (m_ndis_api.ReadPackets(m_read_request) && m_read_request->dwPacketsSuccess > 0) {
                std::vector<std::list<QueuedPacket>> groups(m_num_workers);
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

                        if (ether_type == ETHERTYPE_IP && b->m_Length >= 34) {
                            PIP_HEADER ip = (PIP_HEADER)(buffer + 14);
                            int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;

                            if (ip->Proto == IPPROTO_ICMP && b->m_dwDeviceFlags != PACKET_FLAG_ON_SEND && b->m_Length >= 14 + ip_hdr_len + sizeof(ICMP_HEADER)) {
                                PICMP_HEADER icmp = (PICMP_HEADER)(buffer + 14 + ip_hdr_len);
                                if (icmp->Type == 8 && ip->DstAddr == m_gateway_ip) {
                                    // In-place modification for echo reply
                                    uint8_t tmac[6];
                                    memcpy(tmac, buffer, 6);
                                    memcpy(buffer, buffer + 6, 6);
                                    memcpy(buffer + 6, tmac, 6);
                                    ULONG tip = ip->SrcAddr;
                                    ip->SrcAddr = ip->DstAddr;
                                    ip->DstAddr = tip;
                                    icmp->Type = 0;
                                    recalculate_ip_checksum(ip);
                                    recalculate_tcp_udp_checksum(ip);

                                    std::lock_guard<std::mutex> lock(m_results_queue.mtx);
                                    m_results_queue.packets.push_back({ b, PacketDestination::TO_ADAPTER });
                                    m_read_request->EthPacket[i].Buffer = nullptr; // Buffer ownership transferred
                                    handled = true;
                                }
                            }
                            else if (ip->Proto == IPPROTO_UDP && b->m_Length >= 14 + ip_hdr_len + sizeof(UDP_HEADER)) {
                                PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + ip_hdr_len);
                                USHORT sp = ntohs(udp->SrcPort), dp = ntohs(udp->DstPort);
                                if (sp == 67 || dp == 67 || sp == 68 || dp == 68) { // DHCP Fast Path
                                    // Recalculate checksums to ensure validity after capture
                                    recalculate_ip_checksum(ip);
                                    recalculate_tcp_udp_checksum(ip);

                                    PacketDestination dest = (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) ? PacketDestination::TO_ADAPTER : PacketDestination::TO_MSTCP;
                                    std::lock_guard<std::mutex> lock(m_results_queue.mtx);
                                    m_results_queue.packets.push_back({ b, dest });
                                    m_read_request->EthPacket[i].Buffer = nullptr; // 所有权转移
                                    SetEvent(m_results_event);
                                    handled = true;
                                }
                                else if (sp == 1900 || dp == 1900 || sp == 5353 || dp == 5353) { // Drop Discovery
                                    PacketPool::instance().release(b);
                                    m_read_request->EthPacket[i].Buffer = nullptr; // 释放
                                    handled = true;
                                }
                            }
                        }
                    }

                // --- Slow Path (if not handled by fast path) ---
                if (!handled) {
                    groups[get_target_worker((char*)b->m_IBuffer, b->m_Length, b->m_dwDeviceFlags, m_num_workers)].push_back({ b });
                    m_read_request->EthPacket[i].Buffer = nullptr; // Buffer ownership transferred to worker
                }

                // Replace the used buffer in the read request
                PINTERMEDIATE_BUFFER next_b = PacketPool::instance().acquire();
                if (next_b) {
                    m_read_request->EthPacket[i].Buffer = next_b;
                } else {
                    LOG_ERROR("[Driver] Packet pool exhausted! Stopping read batch.");
                    m_read_request->dwPacketsSuccess = i; // Adjust for partial dispatch
                    break;
                }
            }
            for (unsigned int i = 0; i < m_num_workers; ++i) {
                if (!groups[i].empty()) {
                    std::lock_guard<std::mutex> lock(m_worker_queues[i]->mtx);
                    m_worker_queues[i]->packets.splice(m_worker_queues[i]->packets.end(), groups[i]);
                    m_worker_queues[i]->cv.notify_one();
                }
            }
        }

        // 2. Write Results (DRAIN COMPLETELY)
        {
            std::lock_guard<std::mutex> lock(m_results_queue.mtx);
            if (!m_results_queue.packets.empty()) local_results.splice(local_results.end(), m_results_queue.packets);
        }

        if (!local_results.empty()) {
            std::list<PINTERMEDIATE_BUFFER> to_adapter;
            std::list<PINTERMEDIATE_BUFFER> to_mstcp;

            // Sort packets into separate queues once
            for (auto& pr : local_results) {
                if (pr.destination == PacketDestination::TO_ADAPTER) to_adapter.push_back(pr.buffer);
                else to_mstcp.push_back(pr.buffer);
            }
            local_results.clear();

            // Drain adapter queue
            while (!to_adapter.empty() && m_running) {
                m_write_request->dwPacketsNumber = 0;
                while (!to_adapter.empty() && m_write_request->dwPacketsNumber < BATCH_SIZE) {
                    m_write_request->EthPacket[m_write_request->dwPacketsNumber++].Buffer = to_adapter.front();
                    to_adapter.pop_front();
                }
                m_write_request->hAdapterHandle = m_adapter_handle;
                if (m_ndis_api.SendPacketsToAdapter(m_write_request)) {
                    std::vector<RawPacket*> ptrs;
                    for (unsigned int i = 0; i < m_write_request->dwPacketsNumber; ++i) ptrs.push_back(m_write_request->EthPacket[i].Buffer);
                    PacketPool::instance().release_batch(ptrs.data(), ptrs.size());
                } else {
                    std::vector<RawPacket*> ptrs;
                    for (unsigned int i = 0; i < m_write_request->dwPacketsNumber; ++i) ptrs.push_back(m_write_request->EthPacket[i].Buffer);
                    PacketPool::instance().release_batch(ptrs.data(), ptrs.size());
                }
            }

            // Drain mstcp queue
            while (!to_mstcp.empty() && m_running) {
                m_mstcp_request->dwPacketsNumber = 0;
                while (!to_mstcp.empty() && m_mstcp_request->dwPacketsNumber < BATCH_SIZE) {
                    m_mstcp_request->EthPacket[m_mstcp_request->dwPacketsNumber++].Buffer = to_mstcp.front();
                    to_mstcp.pop_front();
                }
                m_mstcp_request->hAdapterHandle = m_adapter_handle;
                if (m_ndis_api.SendPacketsToMstcp(m_mstcp_request)) {
                    std::vector<RawPacket*> ptrs;
                    for (unsigned int i = 0; i < m_mstcp_request->dwPacketsNumber; ++i) ptrs.push_back(m_mstcp_request->EthPacket[i].Buffer);
                    PacketPool::instance().release_batch(ptrs.data(), ptrs.size());
                } else {
                    std::vector<RawPacket*> ptrs;
                    for (unsigned int i = 0; i < m_mstcp_request->dwPacketsNumber; ++i) ptrs.push_back(m_mstcp_request->EthPacket[i].Buffer);
                    PacketPool::instance().release_batch(ptrs.data(), ptrs.size());
                }
            }
        }

        // 3. Stats
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_last_stat_time).count();
        if (elapsed_ms >= 1000) {
            uint64_t dl_pkts = m_stat_dl_pkts.exchange(0); uint64_t dl_bytes = m_stat_dl_bytes.exchange(0);
            uint64_t ul_pkts = m_stat_ul_pkts.exchange(0); uint64_t ul_bytes = m_stat_ul_bytes.exchange(0);
            uint64_t work_us = m_stat_work_time_us.exchange(0);
            double dl_mbps = (dl_bytes * 8.0) / (elapsed_ms * 1000.0);
            double ul_mbps = (ul_bytes * 8.0) / (elapsed_ms * 1000.0);
            size_t backlog = 0; for (auto& q : m_worker_queues) backlog += q->packets.size();
            uint64_t total_pkts = dl_pkts + ul_pkts;
            LOG_INFO("[Perf] DL: %.2f Mbps (%llu p) | UL: %.2f Mbps (%llu p) | Backlog: %zu | AvgWork: %llu us",
                dl_mbps, dl_pkts, ul_mbps, ul_pkts, backlog, total_pkts > 0 ? work_us / total_pkts : 0);
            m_last_stat_time = now;
        }
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
