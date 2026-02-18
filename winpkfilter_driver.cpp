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
#include <poppack.h>

const USHORT ETHERTYPE_IP = 0x0800;
const USHORT ETHERTYPE_ARP = 0x0806;
const USHORT ETHERTYPE_IPV6 = 0x86DD;

#pragma comment(lib, "ndisapilib.lib")
#pragma comment(lib, "iphlpapi.lib")

const USHORT NAT_TARGET_PORT = 3080;

// Standard 1's complement sum
static uint32_t csum_partial(const void* data, int len, uint32_t start_sum) {
    const uint16_t* ptr = (const uint16_t*)data;
    uint32_t sum = start_sum;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0) {
        sum += *(const uint8_t*)ptr;
    }
    return sum;
}

static uint16_t csum_finalize(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t result = (uint16_t)(~sum);
    if (result == 0) return 0xFFFF;
    return result;
}

static void recalculate_ip_checksum(PIP_HEADER ip) {
    ip->Csum = 0;
    ip->Csum = csum_finalize(csum_partial(ip, (ip->Ver_HLen & 0x0F) * 4, 0));
}

static void recalculate_tcp_udp_checksum(PIP_HEADER ip) {
    int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;
    int payload_len = ntohs(ip->Len) - ip_hdr_len;
    if (payload_len < 0) return;

    // Pseudo-header sum
    uint32_t sum = 0;
    sum += (ip->SrcAddr & 0xFFFF);
    sum += (ip->SrcAddr >> 16);
    sum += (ip->DstAddr & 0xFFFF);
    sum += (ip->DstAddr >> 16);
    sum += htons((uint16_t)ip->Proto);
    sum += htons((uint16_t)payload_len);

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

// Hashing function for 5-tuple to dispatch packets to worker threads
static uint32_t get_flow_hash(const char* packet, size_t length) {
    if (length < 14 + sizeof(IP_HEADER)) {
        return 0; // Not an IP packet
    }

    PIP_HEADER ip = (PIP_HEADER)(packet + 14);
    int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;

    // A simple hash combination
    uint32_t hash = ip->SrcAddr ^ ip->DstAddr ^ ip->Proto;

    if (ip->Proto == IPPROTO_TCP) {
        if (length >= 14 + ip_hdr_len + sizeof(TCP_HEADER)) {
            PTCP_HEADER tcp = (PTCP_HEADER)((uint8_t*)ip + ip_hdr_len);
            hash ^= (tcp->SrcPort << 16) | tcp->DstPort;
        }
    } else if (ip->Proto == IPPROTO_UDP) {
        if (length >= 14 + ip_hdr_len + sizeof(UDP_HEADER)) {
            PUDP_HEADER udp = (PUDP_HEADER)((uint8_t*)ip + ip_hdr_len);
            hash ^= (udp->SrcPort << 16) | udp->DstPort;
        }
    }

    return hash;
}

WinPkFilterDriver::WinPkFilterDriver()
    : m_adapter_handle(nullptr), m_wait_event(nullptr), m_running(false), m_gateway_ip(0) {
    CNdisApi::SetPoolSize(8192);

    m_num_workers = std::thread::hardware_concurrency();
    if (m_num_workers == 0) {
        m_num_workers = 4; // Default to 4 workers if detection fails
    }
    m_worker_queues.resize(m_num_workers);

    m_read_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    m_read_request->dwPacketsNumber = BATCH_SIZE;
    for (int i = 0; i < BATCH_SIZE; ++i) m_read_buffers[i] = nullptr;
    
    m_write_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    m_write_request->dwPacketsNumber = 0;

    m_mstcp_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    m_mstcp_request->dwPacketsNumber = 0;

    m_send_buffer = new INTERMEDIATE_BUFFER();
    memset(m_adapter_mac, 0, 6);
}

WinPkFilterDriver::~WinPkFilterDriver() {
    stop();
    for (int i = 0; i < BATCH_SIZE; ++i) {
        if (m_read_buffers[i]) PacketPool::instance().release(m_read_buffers[i]);
    }
    free(m_read_request);
    free(m_write_request);
    free(m_mstcp_request);
    delete m_send_buffer;
}

std::vector<std::pair<std::string, std::string>> WinPkFilterDriver::get_adapters() {
    std::vector<std::pair<std::string, std::string>> result;
    CNdisApi api;
    if (!api.IsDriverLoaded()) return result;
    TCP_AdapterList adapters;
    if (api.GetTcpipBoundAdaptersInfo(&adapters)) {
        for (UINT i = 0; i < adapters.m_nAdapterCount; ++i) {
            result.push_back({ (char*)adapters.m_szAdapterNameList[i], (char*)adapters.m_szAdapterNameList[i] });
        }
    }
    return result;
}

bool WinPkFilterDriver::start_batch(const std::string& adapter_name, BatchPacketHandler handler) {
    LOG_INFO("[Driver] Initializing WinPkFilter (Multi-threaded Batch Mode) on: %s", adapter_name.c_str());
    if (!m_ndis_api.IsDriverLoaded()) return false;

    for (int i = 0; i < BATCH_SIZE; ++i) {
        if (!m_read_buffers[i]) {
            m_read_buffers[i] = PacketPool::instance().acquire();
            m_read_request->EthPacket[i].Buffer = m_read_buffers[i];
        }
    }

    TCP_AdapterList adapters;
    if (!m_ndis_api.GetTcpipBoundAdaptersInfo(&adapters)) return false;

    bool found = false;
    std::string target_lower = adapter_name;
    std::transform(target_lower.begin(), target_lower.end(), target_lower.begin(), ::tolower);

    for (UINT i = 0; i < adapters.m_nAdapterCount; ++i) {
        std::string current_name = (char*)adapters.m_szAdapterNameList[i];
        std::string current_lower = current_name;
        std::transform(current_lower.begin(), current_lower.end(), current_lower.begin(), ::tolower);
        if (current_lower.find(target_lower) != std::string::npos || target_lower.find(current_lower) != std::string::npos) {
            m_adapter_handle = adapters.m_nAdapterHandle[i];
            found = true;
            LOG_INFO("[Driver] Matched adapter: %s", current_name.c_str());
            break;
        }
    }

    if (!found) return false;

    m_gateway_ip = inet_addr(g_config.tap_ip.c_str());
    get_adapter_mac(adapter_name, m_adapter_mac);

    m_batch_handler = handler;
    m_wait_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!m_ndis_api.SetPacketEvent(m_adapter_handle, m_wait_event)) return false;

    ADAPTER_MODE mode;
    mode.dwFlags = MSTCP_FLAG_SENT_RECEIVE | MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL;
    mode.hAdapterHandle = m_adapter_handle;
    if (!m_ndis_api.SetAdapterMode(&mode)) return false;

    m_running = true;
    
    m_reader_thread = std::thread(&WinPkFilterDriver::run, this);
    SetThreadPriority(m_reader_thread.native_handle(), THREAD_PRIORITY_HIGHEST);

    LOG_INFO("[Driver] Starting %d worker threads", m_num_workers);
    for (unsigned int i = 0; i < m_num_workers; ++i) {
        m_worker_threads.emplace_back(&WinPkFilterDriver::worker_loop, this, i);
        SetThreadPriority(m_worker_threads.back().native_handle(), THREAD_PRIORITY_NORMAL);
    }
    
    return true;
}

void WinPkFilterDriver::stop() {
    m_running = false;
    if (m_wait_event) SetEvent(m_wait_event);

    for (auto& queue : m_worker_queues) {
        queue.cv.notify_all();
    }
    m_results_queue.cv.notify_all();

    if (m_reader_thread.joinable()) m_reader_thread.join();
    
    for (auto& worker : m_worker_threads) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    if (m_adapter_handle) {
        ADAPTER_MODE mode = { m_adapter_handle, 0 };
        m_ndis_api.SetAdapterMode(&mode); 
        m_ndis_api.SetPacketEvent(m_adapter_handle, nullptr);
        m_adapter_handle = nullptr;
    }
    if (m_wait_event) { CloseHandle(m_wait_event); m_wait_event = nullptr; }
}


void WinPkFilterDriver::worker_loop(unsigned int worker_id) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    LOG_INFO("[Driver] Worker thread %d started", worker_id);

    std::list<QueuedPacket> local_queue;
    
    std::vector<Packet> packets_to_process;
    packets_to_process.reserve(BATCH_SIZE);
    
    std::vector<Packet> packets_to_send;
    packets_to_send.reserve(BATCH_SIZE);
    std::vector<Packet> packets_to_mstcp;
    packets_to_mstcp.reserve(BATCH_SIZE);

    while (m_running)
    {
        {
            std::unique_lock<std::mutex> lock(m_worker_queues[worker_id].mtx);
            m_worker_queues[worker_id].cv.wait(lock, [&] {
                return !m_running || !m_worker_queues[worker_id].packets.empty();
            });

            if (!m_running && m_worker_queues[worker_id].packets.empty()) {
                break;
            }
            local_queue.splice(local_queue.end(), m_worker_queues[worker_id].packets);
        }

        if (local_queue.empty()) {
            continue;
        }

        packets_to_process.clear();
        for (auto& p_in : local_queue) {
            packets_to_process.emplace_back(RawPacketPtr(p_in.buffer), (p_in.buffer->m_dwDeviceFlags == PACKET_FLAG_ON_SEND));
        }
        local_queue.clear();

        if (m_batch_handler) {
             m_batch_handler(std::move(packets_to_process));
        }
        
        packets_to_send.clear();
        packets_to_mstcp.clear();

        for (auto& p : packets_to_process) {
            char* buffer = (char*)p.data->m_IBuffer;
            size_t length = p.data->m_Length;

            if (length < 14) {
                p.outbound ? packets_to_send.push_back(std::move(p)) : packets_to_mstcp.push_back(std::move(p));
                continue;
            }

            USHORT ether_type = ntohs(*(USHORT*)(buffer + 12));

            if (ether_type == ETHERTYPE_IPV6) {
                p.outbound ? packets_to_send.push_back(std::move(p)) : packets_to_mstcp.push_back(std::move(p));
                continue;
            }

            if (ether_type == ETHERTYPE_ARP) {
                if (!p.outbound && length >= 14 + sizeof(ARP_HEADER)) {
                    PARP_HEADER arp = (PARP_HEADER)(buffer + 14);
                    if (arp->OpCode == htons(1) && arp->DstIp == m_gateway_ip) {
                        uint8_t reply[60];
                        memset(reply, 0, 60);
                        memcpy(reply, buffer + 6, 6);
                        memcpy(reply + 6, m_adapter_mac, 6);
                        *(USHORT*)(reply + 12) = htons(ETHERTYPE_ARP);
                        PARP_HEADER rarp = (PARP_HEADER)(reply + 14);
                        rarp->HwType = htons(1);
                        rarp->ProtoType = htons(ETHERTYPE_IP);
                        rarp->HwLen = 6;
                        rarp->ProtoLen = 4;
                        rarp->OpCode = htons(2);
                        memcpy(rarp->SrcMac, m_adapter_mac, 6);
                        rarp->SrcIp = m_gateway_ip;
                        memcpy(rarp->DstMac, arp->SrcMac, 6);
                        rarp->DstIp = arp->SrcIp;
                        send_to_adapter((const char*)reply, 60);
                        PacketPool::instance().release(p.data.release()); // Release original packet
                        continue;
                    }
                }
                p.outbound ? packets_to_send.push_back(std::move(p)) : packets_to_mstcp.push_back(std::move(p));
            }
            else if (ether_type == ETHERTYPE_IP) {
                PIP_HEADER ip = (PIP_HEADER)(buffer + 14);
                if (ip->Proto == IPPROTO_ICMP && !p.outbound) {
                    int ip_hdr_len = (ip->Ver_HLen & 0x0F) * 4;
                    if (length >= 14 + ip_hdr_len + sizeof(ICMP_HEADER)) {
                        PICMP_HEADER icmp = (PICMP_HEADER)(buffer + 14 + ip_hdr_len);
                        if (icmp->Type == 8 && ip->DstAddr == m_gateway_ip) { // Echo Request to Gateway
                            // Prepare local Echo Reply
                            uint8_t temp_mac[6];
                            memcpy(temp_mac, buffer, 6);
                            memcpy(buffer, buffer + 6, 6);
                            memcpy(buffer + 6, temp_mac, 6);

                            ULONG temp_ip = ip->SrcAddr;
                            ip->SrcAddr = ip->DstAddr;
                            ip->DstAddr = temp_ip;

                            icmp->Type = 0; // Echo Reply
                            recalculate_ip_checksum(ip);
                            recalculate_tcp_udp_checksum(ip);

                            send_to_adapter(buffer, length);
                            PacketPool::instance().release(p.data.release()); // Release original packet
                            continue;
                        }
                    }
                }

                if (ip->Proto == IPPROTO_UDP) {
                    PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                    USHORT sport = ntohs(udp->SrcPort);
                    USHORT dport = ntohs(udp->DstPort);
                    if (sport == 67 || sport == 68 || dport == 67 || dport == 68 ||
                        sport == 137 || sport == 138 || dport == 137 || dport == 138 ||
                        dport == 5353 || dport == 5355 || dport == 1900) {
                        p.outbound ? packets_to_send.push_back(std::move(p)) : packets_to_mstcp.push_back(std::move(p));
                        continue;
                    }
                }

                if (!p.outbound) {
                    bool intercepted = false;
                    if ((ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP) && ip->SrcAddr != m_gateway_ip) {
                        bool should_intercept = false;
                        if (ip->Proto == IPPROTO_TCP) {
                            if (ip->DstAddr != m_gateway_ip)
                                should_intercept = true;
                            else if (ntohs(((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort) == 53)
                                should_intercept = true;
                        }
                        else {
                            if (ntohs(((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort) == 53)
                                should_intercept = true;
                        }

                        if (should_intercept) {
                            OriginalDestination od(ip->DstAddr, 0, ip->SrcAddr);
                            uint64_t mapping_key = 0;

                            if (ip->Proto == IPPROTO_TCP) {
                                PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                od.port = tcp->DstPort;
                                mapping_key = NatManager::make_key(ip->SrcAddr, tcp->SrcPort);
                                NatManager::instance().create_tcp_mapping(mapping_key, od);
                                ip->DstAddr = m_gateway_ip;
                                tcp->DstPort = htons(NAT_TARGET_PORT);
                            }
                            else {
                                PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                od.port = udp->DstPort;
                                mapping_key = NatManager::make_key(ip->SrcAddr, udp->SrcPort);
                                NatManager::instance().create_or_update_udp_mapping(mapping_key, od);
                                ip->DstAddr = m_gateway_ip;
                                udp->DstPort = htons(NAT_TARGET_PORT);
                            }

                            recalculate_ip_checksum(ip);
                            recalculate_tcp_udp_checksum(ip);

                            packets_to_mstcp.push_back(std::move(p));
                            intercepted = true;
                        }
                    }
                    if (!intercepted)
                        packets_to_mstcp.push_back(std::move(p));
                }
                else { // outbound
                    bool restored = false;
                    if (ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP) {
                        USHORT src_port = 0;
                        if (ip->Proto == IPPROTO_TCP)
                            src_port = ntohs(((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->SrcPort);
                        else
                            src_port = ntohs(((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->SrcPort);

                        if (src_port == NAT_TARGET_PORT) {
                            uint64_t mapping_key = 0;
                            if (ip->Proto == IPPROTO_TCP)
                                mapping_key = NatManager::make_key(ip->DstAddr, ((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort);
                            else
                                mapping_key = NatManager::make_key(ip->DstAddr, ((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort);

                            auto od = NatManager::instance().get_mapping(mapping_key);
                            if (od) {
                                ip->SrcAddr = od->ip;
                                if (ip->Proto == IPPROTO_TCP) {
                                    ((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->SrcPort = od->port;
                                }
                                else {
                                    ((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->SrcPort = od->port;
                                }

                                recalculate_ip_checksum(ip);
                                recalculate_tcp_udp_checksum(ip);

                                packets_to_send.push_back(std::move(p));
                                restored = true;
                            }
                        }
                    }
                    if (!restored)
                        packets_to_send.push_back(std::move(p));
                }
            }
            else {
                p.outbound ? packets_to_send.push_back(std::move(p)) : packets_to_mstcp.push_back(std::move(p));
            }
        }
        
        if (!packets_to_send.empty() || !packets_to_mstcp.empty()) {
            std::unique_lock<std::mutex> lock(m_results_queue.mtx);
            if (!packets_to_send.empty()) {
                for (auto& pkt : packets_to_send) {
                    m_results_queue.packets.push_back({ pkt.data.release(), PacketDestination::TO_ADAPTER });
                }
            }
            if (!packets_to_mstcp.empty()) {
                 for (auto& pkt : packets_to_mstcp) {
                    m_results_queue.packets.push_back({ pkt.data.release(), PacketDestination::TO_MSTCP });
                }
            }
            lock.unlock();
            m_results_queue.cv.notify_one();
        }
        packets_to_process.clear();
    }
    LOG_INFO("[Driver] Worker thread %d finished", worker_id);
}

void WinPkFilterDriver::run() {
    m_read_request->hAdapterHandle = m_adapter_handle;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    std::list<ProcessedPacket> local_results;
    std::vector<ProcessedPacket> packets_to_adapter;
    packets_to_adapter.reserve(BATCH_SIZE * m_num_workers);
    std::vector<ProcessedPacket> packets_to_mstcp;
    packets_to_mstcp.reserve(BATCH_SIZE * m_num_workers);

    // The reader thread waits on two events: new packets from the driver, or new results from the workers
    HANDLE wait_events[2] = { m_wait_event, CreateEvent(nullptr, FALSE, FALSE, nullptr) };
    // This is a hack to get the handle from the condition variable, NOT robust for production
    // In a real scenario, use a dedicated event or a different signaling mechanism
    if (m_results_queue.cv._Get_handle() != nullptr) {
        wait_events[1] = m_results_queue.cv._Get_handle();
    }


    while (m_running) {
        
        DWORD wait_result = WaitForMultipleObjects(2, wait_events, FALSE, 100);

        if (!m_running) break;

        // 1. Read packets from driver and dispatch to workers
        // This should happen if the driver event is signaled or on timeout
        if (wait_result == WAIT_OBJECT_0 || wait_result == WAIT_TIMEOUT) {
            bool has_packets = true;
            while (m_running && has_packets) {
                m_read_request->dwPacketsNumber = BATCH_SIZE;
                m_read_request->dwPacketsSuccess = 0;
                
                if (m_ndis_api.ReadPackets(m_read_request) && m_read_request->dwPacketsSuccess > 0) {
                    for (unsigned int i = 0; i < m_read_request->dwPacketsSuccess; ++i) {
                        PINTERMEDIATE_BUFFER filled_buf = m_read_request->EthPacket[i].Buffer;
                        
                        uint32_t hash = get_flow_hash((const char*)filled_buf->m_IBuffer, filled_buf->m_Length);
                        unsigned int worker_id = hash % m_num_workers;

                        {
                            std::lock_guard<std::mutex> lock(m_worker_queues[worker_id].mtx);
                            m_worker_queues[worker_id].packets.push_back({ filled_buf });
                        }
                        m_worker_queues[worker_id].cv.notify_one();
                        
                        m_read_buffers[i] = PacketPool::instance().acquire();
                        m_read_request->EthPacket[i].Buffer = m_read_buffers[i];
                    }
                } else {
                    has_packets = false;
                }
            }
        }

        // 2. Collect processed packets from workers
        {
            std::unique_lock<std::mutex> lock(m_results_queue.mtx, std::try_to_lock);
            if (lock.owns_lock() && !m_results_queue.packets.empty()) {
                local_results.splice(local_results.end(), m_results_queue.packets);
            }
        }

        if (local_results.empty()) {
            continue;
        }

        packets_to_adapter.clear();
        packets_to_mstcp.clear();

        for (auto const& result : local_results) {
            if (result.destination == PacketDestination::TO_ADAPTER) {
                packets_to_adapter.push_back(result);
            } else {
                packets_to_mstcp.push_back(result);
            }
        }
        local_results.clear();

        // 3. Batch write packets back
        if (!packets_to_adapter.empty()) {
            std::lock_guard<std::mutex> lock(m_write_mutex);
            m_write_request->hAdapterHandle = m_adapter_handle;
            size_t processed = 0;
            while (processed < packets_to_adapter.size()) {
                size_t current_batch = (std::min)(packets_to_adapter.size() - processed, (size_t)BATCH_SIZE);
                m_write_request->dwPacketsNumber = (DWORD)current_batch;
                m_write_request->dwPacketsSuccess = 0;
                for (size_t i = 0; i < current_batch; ++i) {
                    m_write_request->EthPacket[i].Buffer = packets_to_adapter[processed + i].buffer;
                }
                m_ndis_api.SendPacketsToAdapter(m_write_request);
                
                for (size_t i = 0; i < current_batch; ++i) {
                    PacketPool::instance().release(packets_to_adapter[processed + i].buffer);
                }
                processed += current_batch;
            }
        }
        
        if (!packets_to_mstcp.empty()) {
            std::lock_guard<std::mutex> lock(m_write_mutex);
            m_mstcp_request->hAdapterHandle = m_adapter_handle;
             size_t processed = 0;
            while (processed < packets_to_mstcp.size()) {
                size_t current_batch = (std::min)(packets_to_mstcp.size() - processed, (size_t)BATCH_SIZE);
                m_mstcp_request->dwPacketsNumber = (DWORD)current_batch;
                m_mstcp_request->dwPacketsSuccess = 0;
                for (size_t i = 0; i < current_batch; ++i) {
                    m_mstcp_request->EthPacket[i].Buffer = packets_to_mstcp[processed + i].buffer;
                }
                m_ndis_api.SendPacketsToMstcp(m_mstcp_request);

                for (size_t i = 0; i < current_batch; ++i) {
                    PacketPool::instance().release(packets_to_mstcp[processed + i].buffer);
                }
                processed += current_batch;
            }
        }
    }
    if (wait_events[1] != m_results_queue.cv._Get_handle()) {
        CloseHandle(wait_events[1]);
    }
}


bool WinPkFilterDriver::get_adapter_mac(const std::string& adapter_name, uint8_t* mac) {
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr; ULONG outBufLen = 15000;
    pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if (!pAddresses) return false;
    std::string guid = adapter_name; size_t pos = guid.find("{"); if (pos != std::string::npos) guid = guid.substr(pos);
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, pAddresses, &outBufLen) == ERROR_SUCCESS) {
        for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != nullptr; pCurr = pCurr->Next) {
            if (guid.find(pCurr->AdapterName) != std::string::npos && pCurr->PhysicalAddressLength == 6) {
                memcpy(mac, pCurr->PhysicalAddress, 6); free(pAddresses); return true;
            }
        }
    }
    if (pAddresses) free(pAddresses); return false;
}

bool WinPkFilterDriver::send_to_adapter(const char* packet, size_t length) {
    if (!m_adapter_handle) return false;
    std::lock_guard<std::mutex> lock(m_send_mutex);
    size_t clen = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(m_send_buffer->m_IBuffer, packet, clen); m_send_buffer->m_Length = (ULONG)clen;
    m_send_buffer->m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    ETH_REQUEST req = { m_adapter_handle, { m_send_buffer } };
    return m_ndis_api.SendPacketToAdapter(&req) != FALSE;
}

bool WinPkFilterDriver::send_to_mstcp(const char* packet, size_t length) {
    if (!m_adapter_handle) return false;
    std::lock_guard<std::mutex> lock(m_send_mutex);
    size_t clen = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(m_send_buffer->m_IBuffer, packet, clen); m_send_buffer->m_Length = (ULONG)clen;
    m_send_buffer->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    ETH_REQUEST req = { m_adapter_handle, { m_send_buffer } };
    return m_ndis_api.SendPacketToMstcp(&req) != FALSE;
}
