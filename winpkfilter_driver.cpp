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

#pragma comment(lib, "ndisapilib.lib")
#pragma comment(lib, "iphlpapi.lib")

const USHORT NAT_TARGET_PORT = 3080;

// Efficient checksum calculation for small headers
static USHORT fast_checksum(USHORT* buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if (size) cksum += *(UCHAR*)buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

// RFC 1071 Incremental Checksum Update
// NewSum = ~(~OldSum + ~Old + New)
static void update_csum_32(USHORT& csum, ULONG old_val, ULONG new_val) {
    uint32_t sum = (~ntohs(csum)) & 0xFFFF;
    // Subtract old (using 1's complement addition of inverse)
    sum += (~old_val) & 0xFFFF;
    if (sum > 0xFFFF) sum -= 0xFFFF;
    sum += (~old_val) >> 16;
    if (sum > 0xFFFF) sum -= 0xFFFF;
    // Add new
    sum += new_val & 0xFFFF;
    if (sum > 0xFFFF) sum -= 0xFFFF;
    sum += new_val >> 16;
    if (sum > 0xFFFF) sum -= 0xFFFF;
    csum = htons(~((USHORT)sum));
}

static void update_csum_16(USHORT& csum, USHORT old_val, USHORT new_val) {
    uint32_t sum = (~ntohs(csum)) & 0xFFFF;
    sum += (USHORT)(~old_val);
    if (sum > 0xFFFF) sum -= 0xFFFF;
    sum += new_val;
    if (sum > 0xFFFF) sum -= 0xFFFF;
    csum = htons(~((USHORT)sum));
}

WinPkFilterDriver::WinPkFilterDriver()
    : m_adapter_handle(nullptr), m_wait_event(nullptr), m_running(false), m_tx_running(false), m_gateway_ip(0) {
    CNdisApi::SetPoolSize(8192);
    m_tx_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    m_read_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    m_read_request->dwPacketsNumber = BATCH_SIZE;
    for (int i = 0; i < BATCH_SIZE; ++i) m_read_buffers[i] = nullptr;
    m_write_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    m_write_request->dwPacketsNumber = BATCH_SIZE;
    m_mstcp_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    m_mstcp_request->dwPacketsNumber = BATCH_SIZE;
    for (int i = 0; i < BATCH_SIZE; ++i) m_write_buffers[i] = nullptr; 
    m_send_buffer = new INTERMEDIATE_BUFFER();
    memset(m_adapter_mac, 0, 6);
}

WinPkFilterDriver::~WinPkFilterDriver() {
    stop();
    if (m_tx_event) CloseHandle(m_tx_event);
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
    LOG_INFO("[Driver] Initializing WinPkFilter (Batch Mode) on: %s", adapter_name.c_str());
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

    m_running = true; m_tx_running = true;
    m_tx_thread = std::thread(&WinPkFilterDriver::tx_run, this);
    SetThreadPriority(m_tx_thread.native_handle(), THREAD_PRIORITY_HIGHEST);
    m_worker_thread = std::thread(&WinPkFilterDriver::run, this);
    SetThreadPriority(m_worker_thread.native_handle(), THREAD_PRIORITY_HIGHEST);
    return true;
}

void WinPkFilterDriver::run() {
    m_read_request->hAdapterHandle = m_adapter_handle;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    std::vector<Packet> captured_packets;
    captured_packets.reserve(BATCH_SIZE);
    std::vector<Packet> packets_to_send;
    packets_to_send.reserve(BATCH_SIZE);
    std::vector<Packet> packets_to_mstcp;
    packets_to_mstcp.reserve(BATCH_SIZE);

    while (m_running) {
        WaitForSingleObject(m_wait_event, INFINITE);
        if (!m_running) break;

        bool has_packets = true;
        while (m_running && has_packets) {
            captured_packets.clear();
            packets_to_send.clear();
            packets_to_mstcp.clear();

            m_read_request->dwPacketsNumber = BATCH_SIZE;
            m_read_request->dwPacketsSuccess = 0;
            
            if (m_ndis_api.ReadPackets(m_read_request) && m_read_request->dwPacketsSuccess > 0) {
                for (unsigned int i = 0; i < m_read_request->dwPacketsSuccess; ++i) {
                    PINTERMEDIATE_BUFFER filled_buf = m_read_request->EthPacket[i].Buffer;
                    bool outbound = (filled_buf->m_dwDeviceFlags == PACKET_FLAG_ON_SEND);
                    captured_packets.push_back({ RawPacketPtr(filled_buf), outbound });
                    
                    m_read_buffers[i] = PacketPool::instance().acquire();
                    m_read_request->EthPacket[i].Buffer = m_read_buffers[i];
                }
            } else {
                has_packets = false;
            }
            
            if (captured_packets.empty()) continue;

            for (auto& p : captured_packets) {
                char* buffer = (char*)p.data->m_IBuffer;
                size_t length = p.data->m_Length;
                
                if (length < 14) { 
                    p.outbound ? packets_to_send.push_back(std::move(p)) : packets_to_mstcp.push_back(std::move(p)); 
                    continue; 
                }

                USHORT ether_type = ntohs(*(USHORT*)(buffer + 12));

                if (ether_type == ETHERTYPE_ARP) {
                    if (!p.outbound && length >= 14 + sizeof(ARP_HEADER)) {
                        PARP_HEADER arp = (PARP_HEADER)(buffer + 14);
                        if (arp->OpCode == htons(1) && arp->DstIp == m_gateway_ip) {
                            uint8_t reply[60]; memset(reply, 0, 60);
                            memcpy(reply, buffer + 6, 6); 
                            memcpy(reply + 6, m_adapter_mac, 6); 
                            *(USHORT*)(reply + 12) = htons(ETHERTYPE_ARP);
                            PARP_HEADER rarp = (PARP_HEADER)(reply + 14);
                            rarp->HwType = htons(1); rarp->ProtoType = htons(ETHERTYPE_IP);
                            rarp->HwLen = 6; rarp->ProtoLen = 4; rarp->OpCode = htons(2);
                            memcpy(rarp->SrcMac, m_adapter_mac, 6); rarp->SrcIp = m_gateway_ip;
                            memcpy(rarp->DstMac, arp->SrcMac, 6); rarp->DstIp = arp->SrcIp;
                            send_to_adapter((const char*)reply, 60);
                            continue;
                        }
                    }
                    p.outbound ? packets_to_send.push_back(std::move(p)) : packets_to_mstcp.push_back(std::move(p));
                } else if (ether_type == ETHERTYPE_IP) {
                    PIP_HEADER ip = (PIP_HEADER)(buffer + 14);

                    if (ip->Proto == IPPROTO_UDP) {
                        PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                        USHORT sport = ntohs(udp->SrcPort); USHORT dport = ntohs(udp->DstPort);
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
                                if (ip->DstAddr != m_gateway_ip) should_intercept = true;
                                else if (ntohs(((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort) == 53) should_intercept = true;
                            } else {
                                if (ntohs(((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort) == 53) should_intercept = true;
                            }

                            if (should_intercept) {
                                uint16_t original_dst_port = 0;
                                ULONG old_dst_ip = ip->DstAddr;
                                USHORT old_dst_port = 0;

                                if (ip->Proto == IPPROTO_TCP) {
                                    PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                    original_dst_port = tcp->DstPort;
                                    old_dst_port = tcp->DstPort;
                                    
                                    OriginalDestination od(ip->DstAddr, original_dst_port, ip->SrcAddr);
                                    uint64_t mapping_key = NatManager::make_key(ip->SrcAddr, tcp->SrcPort);
                                    NatManager::instance().create_tcp_mapping(mapping_key, od);
                                    
                                    ip->DstAddr = m_gateway_ip; 
                                    tcp->DstPort = htons(NAT_TARGET_PORT);
                                    
                                    // Incremental Checksum Updates
                                    update_csum_32(ip->Csum, old_dst_ip, ip->DstAddr);
                                    update_csum_32(tcp->Csum, old_dst_ip, ip->DstAddr);
                                    update_csum_16(tcp->Csum, old_dst_port, tcp->DstPort);
                                } else {
                                    PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                    original_dst_port = udp->DstPort;
                                    old_dst_port = udp->DstPort;

                                    OriginalDestination od(ip->DstAddr, original_dst_port, ip->SrcAddr);
                                    uint64_t mapping_key = NatManager::make_key(ip->SrcAddr, udp->SrcPort);
                                    NatManager::instance().create_or_update_udp_mapping(mapping_key, od);
                                    
                                    ip->DstAddr = m_gateway_ip; 
                                    udp->DstPort = htons(NAT_TARGET_PORT);
                                    
                                    update_csum_32(ip->Csum, old_dst_ip, ip->DstAddr);
                                    if (udp->Csum != 0) {
                                        update_csum_32(udp->Csum, old_dst_ip, ip->DstAddr);
                                        update_csum_16(udp->Csum, old_dst_port, udp->DstPort);
                                    }
                                }
                                packets_to_mstcp.push_back(std::move(p));
                                intercepted = true;
                            }
                        }
                        if (!intercepted) packets_to_mstcp.push_back(std::move(p));
                    } else {
                        bool restored = false;
                        if (ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP) {
                            USHORT src_port = 0;
                            if (ip->Proto == IPPROTO_TCP) src_port = ntohs(((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->SrcPort);
                            else src_port = ntohs(((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->SrcPort);

                            if (src_port == NAT_TARGET_PORT) {
                                uint64_t mapping_key = 0;
                                if (ip->Proto == IPPROTO_TCP) mapping_key = NatManager::make_key(ip->DstAddr, ((PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort);
                                else mapping_key = NatManager::make_key(ip->DstAddr, ((PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4))->DstPort);

                                auto od = NatManager::instance().get_mapping(mapping_key);
                                if (od) {
                                    ULONG old_src_ip = ip->SrcAddr;
                                    ULONG old_dst_ip = ip->DstAddr;
                                    ip->SrcAddr = od->ip;
                                    ip->DstAddr = od->original_client_ip; 
                                    
                                    if (ip->Proto == IPPROTO_TCP) {
                                        PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                        USHORT old_src_port = tcp->SrcPort;
                                        tcp->SrcPort = od->port;
                                        
                                        update_csum_32(ip->Csum, old_src_ip, ip->SrcAddr);
                                        update_csum_32(ip->Csum, old_dst_ip, ip->DstAddr);
                                        update_csum_32(tcp->Csum, old_src_ip, ip->SrcAddr);
                                        update_csum_32(tcp->Csum, old_dst_ip, ip->DstAddr);
                                        update_csum_16(tcp->Csum, old_src_port, tcp->SrcPort);
                                    } else {
                                        PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                        USHORT old_src_port = udp->SrcPort;
                                        udp->SrcPort = od->port;
                                        
                                        update_csum_32(ip->Csum, old_src_ip, ip->SrcAddr);
                                        update_csum_32(ip->Csum, old_dst_ip, ip->DstAddr);
                                        if (udp->Csum != 0) {
                                            update_csum_32(udp->Csum, old_src_ip, ip->SrcAddr);
                                            update_csum_32(udp->Csum, old_dst_ip, ip->DstAddr);
                                            update_csum_16(udp->Csum, old_src_port, udp->SrcPort);
                                        }
                                    }
                                    packets_to_send.push_back(std::move(p));
                                    restored = true;
                                }
                            }
                        }
                        if (!restored) packets_to_send.push_back(std::move(p));
                    }
                } else { 
                    p.outbound ? packets_to_send.push_back(std::move(p)) : packets_to_mstcp.push_back(std::move(p)); 
                }
            }

            if (!packets_to_send.empty()) send_packets_to_adapter(std::move(packets_to_send));
            if (!packets_to_mstcp.empty()) {
                size_t processed = 0;
                m_mstcp_request->hAdapterHandle = m_adapter_handle;
                while (processed < packets_to_mstcp.size()) {
                    size_t current_batch = (std::min)(packets_to_mstcp.size() - processed, (size_t)BATCH_SIZE);
                    m_mstcp_request->dwPacketsNumber = (DWORD)current_batch;
                    m_mstcp_request->dwPacketsSuccess = 0;
                    for (size_t i = 0; i < current_batch; ++i) m_mstcp_request->EthPacket[i].Buffer = packets_to_mstcp[processed + i].data.get();
                    m_ndis_api.SendPacketsToMstcp(m_mstcp_request);
                    processed += current_batch;
                }
            }
        }
    }
}

void WinPkFilterDriver::stop() {
    m_running = false; m_tx_running = false;
    if (m_wait_event) SetEvent(m_wait_event);
    if (m_tx_event) SetEvent(m_tx_event);
    if (m_worker_thread.joinable()) m_worker_thread.join();
    if (m_tx_thread.joinable()) m_tx_thread.join();
    if (m_adapter_handle) {
        ADAPTER_MODE mode = { m_adapter_handle, 0 };
        m_ndis_api.SetAdapterMode(&mode); m_ndis_api.SetPacketEvent(m_adapter_handle, nullptr);
        m_adapter_handle = nullptr;
    }
    if (m_wait_event) { CloseHandle(m_wait_event); m_wait_event = nullptr; }
}

void WinPkFilterDriver::tx_run() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    while (m_tx_running) {
        WaitForSingleObject(m_tx_event, INFINITE);
        if (!m_tx_running) break;
        std::vector<std::vector<Packet>> local_queue;
        { std::lock_guard<std::mutex> lock(m_tx_mtx); local_queue.swap(m_tx_queue); }
        if (local_queue.empty()) continue;
        std::lock_guard<std::mutex> lock(m_write_mutex);
        m_write_request->hAdapterHandle = m_adapter_handle;
        for (auto& packets : local_queue) {
            size_t processed = 0;
            while (processed < packets.size()) {
                size_t current_batch = (std::min)(packets.size() - processed, (size_t)BATCH_SIZE);
                m_write_request->dwPacketsNumber = (DWORD)current_batch;
                m_write_request->dwPacketsSuccess = 0;
                for (size_t i = 0; i < current_batch; ++i) m_write_request->EthPacket[i].Buffer = packets[processed + i].data.get();
                m_ndis_api.SendPacketsToAdapter(m_write_request);
                processed += current_batch;
            }
        }
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

bool WinPkFilterDriver::send_packets_to_adapter(std::vector<Packet>&& packets) {
    if (!m_adapter_handle || packets.empty()) return false;
    { std::lock_guard<std::mutex> lock(m_tx_mtx); m_tx_queue.push_back(std::move(packets)); }
    SetEvent(m_tx_event); return true;
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
