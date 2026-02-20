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
} IP_HEADER, *PIP_HEADER;

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
} TCP_HEADER, *PTCP_HEADER;

typedef struct _UDP_HEADER {
    USHORT  SrcPort;
    USHORT  DstPort;
    USHORT  Len;
    USHORT  Csum;
} UDP_HEADER, *PUDP_HEADER;

typedef struct _ICMP_HEADER {
    UCHAR   Type;
    UCHAR   Code;
    USHORT  Csum;
    USHORT  Id;
    USHORT  Seq;
} ICMP_HEADER, *PICMP_HEADER;

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
} ARP_HEADER, *PARP_HEADER;

typedef struct _PSD_HEADER {
    ULONG  SrcAddr;
    ULONG  DstAddr;
    UCHAR  Zero;
    UCHAR  Proto;
    USHORT Len;
} PSD_HEADER, *PPSD_HEADER;

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
    } else if (ip->Proto == IPPROTO_UDP) {
        PUDP_HEADER udp = (PUDP_HEADER)((uint8_t*)ip + ip_hdr_len);
        udp->Csum = 0;
        udp->Csum = csum_finalize(csum_partial(udp, payload_len, sum));
    } else if (ip->Proto == IPPROTO_ICMP) {
        PICMP_HEADER icmp = (PICMP_HEADER)((uint8_t*)ip + ip_hdr_len);
        icmp->Csum = 0;
        icmp->Csum = csum_finalize(csum_partial(icmp, payload_len, 0));
    }
}

static void incremental_checksum_update(uint16_t* checksum, uint16_t old_val, uint16_t new_val) {
    uint32_t sum = (~(*checksum)) & 0xFFFF;
    sum += (~old_val) & 0xFFFF;
    sum += new_val;
    while (sum >> 16) { sum = (sum & 0xFFFF) + (sum >> 16); }
    *checksum = ~((uint16_t)sum);
}

static void incremental_checksum_update_32(uint16_t* checksum, uint32_t old_val, uint32_t new_val) {
    uint32_t sum = (~(*checksum)) & 0xFFFF;
    sum += (~(old_val & 0xFFFF)) & 0xFFFF;
    sum += (~(old_val >> 16)) & 0xFFFF;
    sum += (new_val & 0xFFFF);
    sum += (new_val >> 16);
    while (sum >> 16) { sum = (sum & 0xFFFF) + (sum >> 16); }
    *checksum = ~((uint16_t)sum);
}

static uint32_t get_flow_hash(const char* packet, size_t length) {
    if (length < 14 + sizeof(IP_HEADER)) return 0;
    PIP_HEADER ip = (PIP_HEADER)(packet + 14);
    uint32_t hash = ip->SrcAddr ^ ip->DstAddr ^ ip->Proto;
    int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;
    if (ip->Proto == IPPROTO_TCP && length >= 14 + ip_hdr_len + sizeof(TCP_HEADER)) {
        PTCP_HEADER tcp = (PTCP_HEADER)((uint8_t*)ip + ip_hdr_len);
        hash ^= (tcp->SrcPort ^ tcp->DstPort); 
    } else if (ip->Proto == IPPROTO_UDP && length >= 14 + ip_hdr_len + sizeof(UDP_HEADER)) {
        PUDP_HEADER udp = (PUDP_HEADER)((uint8_t*)ip + ip_hdr_len);
        hash ^= (udp->SrcPort ^ udp->DstPort);
    }
    return hash;
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
    SetThreadPriority(m_reader_thread.native_handle(), THREAD_PRIORITY_HIGHEST);
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
    while (m_running) {
        {
            std::unique_lock<std::mutex> lock(m_worker_queues[worker_id]->mtx);
            m_worker_queues[worker_id]->cv.wait(lock, [&] { return !m_running || !m_worker_queues[worker_id]->packets.empty(); });
            if (!m_running && m_worker_queues[worker_id]->packets.empty()) break;
            local_queue.splice(local_queue.end(), m_worker_queues[worker_id]->packets);
        }
        
        auto start_time = std::chrono::steady_clock::now();
        std::vector<ProcessedPacket> results;
        
        for (auto& p_in : local_queue) {
            PINTERMEDIATE_BUFFER buffer_ptr = p_in.buffer;
            unsigned char* buffer = buffer_ptr->m_IBuffer;
            size_t length = buffer_ptr->m_Length;
            bool outbound = (buffer_ptr->m_dwDeviceFlags == PACKET_FLAG_ON_SEND);
            bool handled = false;

            if (length >= 14 + 20) {
                PIP_HEADER ip = (PIP_HEADER)(buffer + 14);
                int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;
                if (ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP) {
                    if (!outbound && ip->SrcAddr != m_gateway_ip) {
                        // Inbound: Redirect to Gateway
                        OriginalDestination od(ip->DstAddr, 0, ip->SrcAddr);
                        uint64_t key = 0;
                        uint32_t old_dst_ip = ip->DstAddr;
                        if (ip->Proto == IPPROTO_TCP) {
                            PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + ip_hdr_len);
                            od.port = tcp->DstPort;
                            key = NatManager::make_key(ip->SrcAddr, tcp->SrcPort);
                            NatManager::instance().create_tcp_mapping(key, od);
                            ip->DstAddr = m_gateway_ip;
                            uint16_t old_dst_port = tcp->DstPort;
                            tcp->DstPort = htons(NAT_TARGET_PORT);
                            incremental_checksum_update(&ip->Csum, old_dst_ip, ip->DstAddr);
                            incremental_checksum_update(&tcp->Csum, old_dst_ip, ip->DstAddr);
                            incremental_checksum_update(&tcp->Csum, old_dst_port, tcp->DstPort);
                        } else {
                            PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + ip_hdr_len);
                            od.port = udp->DstPort;
                            key = NatManager::make_key(ip->SrcAddr, udp->SrcPort);
                            NatManager::instance().create_or_update_udp_mapping(key, od);
                            ip->DstAddr = m_gateway_ip;
                            uint16_t old_dst_port = udp->DstPort;
                            udp->DstPort = htons(NAT_TARGET_PORT);
                            incremental_checksum_update(&ip->Csum, old_dst_ip, ip->DstAddr);
                            incremental_checksum_update(&udp->Csum, old_dst_ip, ip->DstAddr);
                            incremental_checksum_update(&udp->Csum, old_dst_port, udp->DstPort);
                        }
                        results.push_back({ buffer_ptr, PacketDestination::TO_MSTCP });
                        handled = true;
                    } else if (outbound) {
                        // Outbound: Recover Original Address
                        uint16_t sport = 0;
                        if (ip->Proto == IPPROTO_TCP) sport = ntohs(((PTCP_HEADER)((char*)ip + ip_hdr_len))->SrcPort);
                        else sport = ntohs(((PUDP_HEADER)((char*)ip + ip_hdr_len))->SrcPort);

                        if (sport == NAT_TARGET_PORT) {
                            uint64_t key = 0;
                            if (ip->Proto == IPPROTO_TCP) key = NatManager::make_key(ip->DstAddr, ((PTCP_HEADER)((char*)ip + ip_hdr_len))->DstPort);
                            else key = NatManager::make_key(ip->DstAddr, ((PUDP_HEADER)((char*)ip + ip_hdr_len))->DstPort);

                            auto od = NatManager::instance().get_mapping(key);
                            if (od) {
                                uint32_t old_src_ip = ip->SrcAddr;
                                ip->SrcAddr = od->ip;
                                incremental_checksum_update(&ip->Csum, old_src_ip, ip->SrcAddr);
                                if (ip->Proto == IPPROTO_TCP) {
                                    PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + ip_hdr_len);
                                    uint16_t old_src_port = tcp->SrcPort;
                                    tcp->SrcPort = od->port;
                                    incremental_checksum_update(&tcp->Csum, old_src_ip, ip->SrcAddr);
                                    incremental_checksum_update(&tcp->Csum, old_src_port, tcp->SrcPort);
                                } else {
                                    PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + ip_hdr_len);
                                    uint16_t old_src_port = udp->SrcPort;
                                    udp->SrcPort = od->port;
                                    incremental_checksum_update(&udp->Csum, old_src_ip, ip->SrcAddr);
                                    incremental_checksum_update(&udp->Csum, old_src_port, udp->SrcPort);
                                }
                            } else {
                                recalculate_ip_checksum(ip);
                                recalculate_tcp_udp_checksum(ip);
                            }
                        }
                        results.push_back({ buffer_ptr, PacketDestination::TO_ADAPTER });
                        handled = true;
                    }
                }
            }
            if (!handled) {
                results.push_back({ buffer_ptr, outbound ? PacketDestination::TO_ADAPTER : PacketDestination::TO_MSTCP });
            }
        }
        
        m_stat_work_time_us += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time).count();
        local_queue.clear();
        if (!results.empty()) {
            std::lock_guard<std::mutex> lock(m_results_queue.mtx);
            m_results_queue.packets.splice(m_results_queue.packets.end(), std::list<ProcessedPacket>(std::make_move_iterator(results.begin()), std::make_move_iterator(results.end())));
            SetEvent(m_results_event);
        }
    }
}

void WinPkFilterDriver::run() {
    std::list<ProcessedPacket> local_results;
    HANDLE wait_events[2] = { m_wait_event, m_results_event };
    
    in_addr gateway_addr_struct{};
    inet_pton(AF_INET, g_config.tap_ip.c_str(), &gateway_addr_struct);
    ULONG gateway_ip = gateway_addr_struct.s_addr;

    while (m_running) {
        WaitForMultipleObjects(2, wait_events, FALSE, 10);
        if (!m_running) break;

        // 1. Read & Dispatch
        m_read_request->dwPacketsNumber = BATCH_SIZE;
        if (m_ndis_api.ReadPackets(m_read_request) && m_read_request->dwPacketsSuccess > 0) {
            std::vector<std::list<QueuedPacket>> groups(m_num_workers);
            for (unsigned int i = 0; i < m_read_request->dwPacketsSuccess; ++i) {
                PINTERMEDIATE_BUFFER b = m_read_request->EthPacket[i].Buffer;
                bool handled = false;

                if (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) {
                    m_stat_ul_pkts++; m_stat_ul_bytes += b->m_Length;
                } else {
                    m_stat_dl_pkts++; m_stat_dl_bytes += b->m_Length;
                }

                if (b->m_Length >= 14) {
                    unsigned char* buffer = b->m_IBuffer;
                    USHORT ether_type = ntohs(*(USHORT*)(buffer + 12));

                    if (ether_type == ETHERTYPE_ARP && b->m_Length >= 14 + sizeof(ARP_HEADER)) {
                        PARP_HEADER arp = (PARP_HEADER)(buffer + 14);
                        if (b->m_dwDeviceFlags != PACKET_FLAG_ON_SEND && arp->OpCode == htons(1) && arp->DstIp == gateway_ip) {
                            PINTERMEDIATE_BUFFER rb = PacketPool::instance().acquire();
                            if (rb) {
                                uint8_t* r = rb->m_IBuffer;
                                memcpy(r, buffer + 6, 6); memcpy(r + 6, m_adapter_mac, 6);
                                *(USHORT*)(r + 12) = htons(ETHERTYPE_ARP);
                                PARP_HEADER ra = (PARP_HEADER)(r + 14);
                                ra->HwType = htons(1); ra->ProtoType = htons(ETHERTYPE_IP); ra->HwLen = 6; ra->ProtoLen = 4; ra->OpCode = htons(2);
                                memcpy(ra->SrcMac, m_adapter_mac, 6); ra->SrcIp = gateway_ip; memcpy(ra->DstMac, arp->SrcMac, 6); ra->DstIp = arp->SrcIp;
                                rb->m_Length = 60;
                                std::lock_guard<std::mutex> lock(m_results_queue.mtx);
                                m_results_queue.packets.push_back({ rb, PacketDestination::TO_ADAPTER });
                                SetEvent(m_results_event);
                            }
                            handled = true;
                        }
                    } else if (ether_type == ETHERTYPE_IP && b->m_Length >= 34) {
                        PIP_HEADER ip = (PIP_HEADER)(buffer + 14);
                        int ihl = (ip->Ver_HLen & 0x0F) * 4;
                        if (ip->Proto == IPPROTO_ICMP && b->m_dwDeviceFlags != PACKET_FLAG_ON_SEND) {
                            PICMP_HEADER icmp = (PICMP_HEADER)(buffer + 14 + ihl);
                            if (icmp->Type == 8 && ip->DstAddr == gateway_ip) {
                                uint8_t tmac[6]; memcpy(tmac, buffer, 6); memcpy(buffer, buffer + 6, 6); memcpy(buffer + 6, tmac, 6);
                                ULONG tip = ip->SrcAddr; ip->SrcAddr = ip->DstAddr; ip->DstAddr = tip;
                                icmp->Type = 0; recalculate_ip_checksum(ip); recalculate_tcp_udp_checksum(ip);
                                {
                                    std::lock_guard<std::mutex> lock(m_results_queue.mtx);
                                    m_results_queue.packets.push_back({ b, PacketDestination::TO_ADAPTER });
                                }
                                m_read_request->EthPacket[i].Buffer = nullptr;
                                SetEvent(m_results_event);
                                handled = true;
                            }
                        } else if (ip->Proto == IPPROTO_UDP && b->m_Length >= 14 + ihl + 8) {
                            PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + ihl);
                            USHORT sp = ntohs(udp->SrcPort), dp = ntohs(udp->DstPort);
                            if (sp == 67 || dp == 67 || sp == 68 || dp == 68) {
                                PacketDestination d = (b->m_dwDeviceFlags == PACKET_FLAG_ON_SEND) ? PacketDestination::TO_ADAPTER : PacketDestination::TO_MSTCP;
                                {
                                    std::lock_guard<std::mutex> lock(m_results_queue.mtx);
                                    m_results_queue.packets.push_back({ b, d });
                                }
                                m_read_request->EthPacket[i].Buffer = nullptr; handled = true;
                                SetEvent(m_results_event);
                            } else if (sp == 1900 || dp == 1900 || sp == 5353 || dp == 5353) {
                                PacketPool::instance().release(b); m_read_request->EthPacket[i].Buffer = nullptr; handled = true;
                            }
                        } else if (ip->Proto == IPPROTO_TCP && b->m_Length >= 14 + ihl + 20) {
                            PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + ihl);
                            int thl = (tcp->HdrLen >> 4) * 4;
                            if (b->m_dwDeviceFlags != PACKET_FLAG_ON_SEND && ntohs(tcp->DstPort) == 80) {
                                int pl = ntohs(ip->Len) - ihl - thl;
                                bool hook = (ip->DstAddr == gateway_ip);
                                if (!hook && pl > 0) hook = is_generate_204_request((unsigned char*)tcp + thl, (size_t)pl);
                                if (hook && pl > 0) {
                                    PINTERMEDIATE_BUFFER rb = PacketPool::instance().acquire();
                                    if (rb) {
                                        unsigned char* r = rb->m_IBuffer;
                                        memcpy(r, buffer + 6, 6); memcpy(r + 6, buffer, 6); *(USHORT*)(r + 12) = htons(0x0800);
                                        PIP_HEADER ri = (PIP_HEADER)(r + 14);
                                        ri->Ver_HLen = 0x45; ri->TOS = 0; ri->ID = htons(0x1234); ri->Flags_Frag = 0; ri->TTL = 64; ri->Proto = IPPROTO_TCP;
                                        ri->SrcAddr = ip->DstAddr; ri->DstAddr = ip->SrcAddr;
                                        PTCP_HEADER rt = (PTCP_HEADER)((char*)ri + 20);
                                        rt->SrcPort = tcp->DstPort; rt->DstPort = tcp->SrcPort;
                                        rt->SeqNum = tcp->AckNum; rt->AckNum = htonl(ntohl(tcp->SeqNum) + (uint32_t)pl);
                                        rt->HdrLen = 0x50; rt->Flags = 0x19; rt->WinSize = htons(65535); rt->UrgPtr = 0;
                                        const char* c = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                                        int cl = (int)strlen(c); memcpy((char*)rt + 20, c, cl);
                                        ri->Len = htons(40 + cl); rb->m_Length = 14 + 40 + cl;
                                        recalculate_ip_checksum(ri); recalculate_tcp_udp_checksum(ri);
                                        {
                                            std::lock_guard<std::mutex> lock(m_results_queue.mtx);
                                            m_results_queue.packets.push_back({ rb, PacketDestination::TO_ADAPTER });
                                        }
                                        SetEvent(m_results_event);
                                    }
                                    PacketPool::instance().release(b); m_read_request->EthPacket[i].Buffer = nullptr; handled = true;
                                }
                            }
                        }
                    }
                }

                if (!handled) {
                    groups[get_flow_hash((char*)b->m_IBuffer, b->m_Length) % m_num_workers].push_back({ b });
                    m_read_request->EthPacket[i].Buffer = nullptr;
                }

                if (m_read_request->EthPacket[i].Buffer == nullptr) {
                    m_read_request->EthPacket[i].Buffer = PacketPool::instance().acquire();
                }
            }
            for (unsigned int j = 0; j < m_num_workers; ++j) {
                if (!groups[j].empty()) {
                    std::lock_guard<std::mutex> lock(m_worker_queues[j]->mtx);
                    m_worker_queues[j]->packets.splice(m_worker_queues[j]->packets.end(), groups[j]);
                    m_worker_queues[j]->cv.notify_one();
                }
            }
        } else break;

        // 2. Write Results
        {
            std::lock_guard<std::mutex> lock(m_results_queue.mtx);
            if (!m_results_queue.packets.empty()) local_results.splice(local_results.end(), m_results_queue.packets);
        }
        if (!local_results.empty()) {
            m_write_request->hAdapterHandle = m_adapter_handle; m_mstcp_request->hAdapterHandle = m_adapter_handle;
            auto it = local_results.begin();
            while (it != local_results.end()) {
                m_write_request->dwPacketsNumber = 0; m_mstcp_request->dwPacketsNumber = 0;
                while (it != local_results.end() && m_write_request->dwPacketsNumber < BATCH_SIZE && m_mstcp_request->dwPacketsNumber < BATCH_SIZE) {
                    if (it->destination == PacketDestination::TO_ADAPTER) m_write_request->EthPacket[m_write_request->dwPacketsNumber++].Buffer = it->buffer;
                    else m_mstcp_request->EthPacket[m_mstcp_request->dwPacketsNumber++].Buffer = it->buffer;
                    it = local_results.erase(it);
                }
                if (m_write_request->dwPacketsNumber > 0) {
                    if (m_ndis_api.SendPacketsToAdapter(m_write_request)) {
                        for (UINT j = 0; j < m_write_request->dwPacketsNumber; ++j) PacketPool::instance().release(m_write_request->EthPacket[j].Buffer);
                    } else {
                        for (UINT j = 0; j < m_write_request->dwPacketsNumber; ++j) local_results.push_back({ m_write_request->EthPacket[j].Buffer, PacketDestination::TO_ADAPTER });
                    }
                }
                if (m_mstcp_request->dwPacketsNumber > 0) {
                    if (m_ndis_api.SendPacketsToMstcp(m_mstcp_request)) {
                        for (UINT j = 0; j < m_mstcp_request->dwPacketsNumber; ++j) PacketPool::instance().release(m_mstcp_request->EthPacket[j].Buffer);
                    } else {
                        for (UINT j = 0; j < m_mstcp_request->dwPacketsNumber; ++j) local_results.push_back({ m_mstcp_request->EthPacket[j].Buffer, PacketDestination::TO_MSTCP });
                    }
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
            size_t backlog = 0; for(auto& q : m_worker_queues) backlog += q->packets.size();
            uint64_t total_pkts = dl_pkts + ul_pkts;
            LOG_INFO("[Perf] DL: %.2f Mbps (%llu p) | UL: %.2f Mbps (%llu p) | Backlog: %zu | AvgWork: %llu us", 
                dl_mbps, dl_pkts, ul_mbps, ul_pkts, backlog, total_pkts > 0 ? work_us / total_pkts : 0);
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