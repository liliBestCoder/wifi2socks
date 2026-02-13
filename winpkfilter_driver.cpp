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

// Helper to calculate TCP/UDP checksum
USHORT checksum(USHORT* buffer, int size) {
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

typedef struct _PSEUDO_HEADER {
    ULONG   SrcAddr;
    ULONG   DstAddr;
    UCHAR   Zero;
    UCHAR   Proto;
    USHORT  Len;
} PSEUDO_HEADER, *PPSEUDO_HEADER;

USHORT recalculate_tcp_checksum(PIP_HEADER ip_header) {
    PTCP_HEADER tcp_header = (PTCP_HEADER)((UCHAR*)ip_header + (ip_header->Ver_HLen & 0x0F) * 4);
    int tcp_len = ntohs(ip_header->Len) - (ip_header->Ver_HLen & 0x0F) * 4;
    tcp_header->Csum = 0;
    PSEUDO_HEADER pseudo_header;
    pseudo_header.SrcAddr = ip_header->SrcAddr;
    pseudo_header.DstAddr = ip_header->DstAddr;
    pseudo_header.Zero = 0;
    pseudo_header.Proto = ip_header->Proto;
    pseudo_header.Len = htons((USHORT)tcp_len);
    int total_len = sizeof(PSEUDO_HEADER) + tcp_len;
    if (total_len % 2 != 0) total_len++;
    char* checksum_buf = new char[total_len];
    memset(checksum_buf, 0, total_len);
    memcpy(checksum_buf, &pseudo_header, sizeof(PSEUDO_HEADER));
    memcpy(checksum_buf + sizeof(PSEUDO_HEADER), tcp_header, tcp_len);
    tcp_header->Csum = checksum((USHORT*)checksum_buf, total_len);
    delete[] checksum_buf;
    return tcp_header->Csum;
}

USHORT recalculate_udp_checksum(PIP_HEADER ip_header) {
    PUDP_HEADER udp_header = (PUDP_HEADER)((UCHAR*)ip_header + (ip_header->Ver_HLen & 0x0F) * 4);
    int udp_len = ntohs(ip_header->Len) - (ip_header->Ver_HLen & 0x0F) * 4;
    udp_header->Csum = 0;
    PSEUDO_HEADER pseudo_header;
    pseudo_header.SrcAddr = ip_header->SrcAddr;
    pseudo_header.DstAddr = ip_header->DstAddr;
    pseudo_header.Zero = 0;
    pseudo_header.Proto = ip_header->Proto;
    pseudo_header.Len = htons((USHORT)udp_len);
    int total_len = sizeof(PSEUDO_HEADER) + udp_len;
    if (total_len % 2 != 0) total_len++;
    char* checksum_buf = new char[total_len];
    memset(checksum_buf, 0, total_len);
    memcpy(checksum_buf, &pseudo_header, sizeof(PSEUDO_HEADER));
    memcpy(checksum_buf + sizeof(PSEUDO_HEADER), udp_header, udp_len);
    udp_header->Csum = checksum((USHORT*)checksum_buf, total_len);
    delete[] checksum_buf;
    return udp_header->Csum;
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

    // Initialize Gateway IP and Adapter MAC
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
    m_worker_thread = std::thread(&WinPkFilterDriver::run, this);
    return true;
}

void WinPkFilterDriver::run() {
    m_read_request->hAdapterHandle = m_adapter_handle;

    while (m_running) {
        WaitForSingleObject(m_wait_event, INFINITE);
        if (!m_running) break;

        std::vector<Packet> packets_to_send;
        std::vector<Packet> packets_to_mstcp;

        bool has_packets = true;
        while (m_running && has_packets) {
            std::vector<Packet> captured_packets;
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
            } else has_packets = false;
            
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
                            LOG_DEBUG("[ARP] Replying to ARP request for gateway %s", g_config.tap_ip.c_str());
                            uint8_t reply[60]; memset(reply, 0, 60);
                            memcpy(reply, buffer + 6, 6); // Dest MAC = Sender MAC
                            memcpy(reply + 6, m_adapter_mac, 6); // Src MAC = Our MAC
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

                    // --- 1. Global UDP Exemption (DHCP, Discovery, etc.) ---
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
                        // --- 2. Inbound: Client to Host (INTERCEPT) ---
                        bool intercepted = false;
                        if (ip->Proto == IPPROTO_TCP || ip->Proto == IPPROTO_UDP) {
                            bool should_intercept = false;
                            if (ip->Proto == IPPROTO_TCP) {
                                if (ip->DstAddr != m_gateway_ip) should_intercept = true;
                                else {
                                    PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                    if (ntohs(tcp->DstPort) == 53) should_intercept = true;
                                }
                            } else {
                                PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                if (ntohs(udp->DstPort) == 53) should_intercept = true;
                            }

                            if (should_intercept) {
                                ClientKey ck = { ip->SrcAddr, 0 };
                                OriginalDestination od = { ip->DstAddr, 0 };
                                if (ip->Proto == IPPROTO_TCP) {
                                    PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                    ck.port = tcp->SrcPort; od.port = tcp->DstPort;
                                    NatManager::instance().create_tcp_mapping(ck, od);
                                    ip->DstAddr = m_gateway_ip; tcp->DstPort = htons(NAT_TARGET_PORT);
                                    ip->Csum = 0; ip->Csum = checksum((USHORT*)ip, (ip->Ver_HLen & 0x0F) * 4);
                                    recalculate_tcp_checksum(ip);
                                } else {
                                    PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                    ck.port = udp->SrcPort; od.port = udp->DstPort;
                                    NatManager::instance().create_or_update_udp_mapping(ck, od);
                                    ip->DstAddr = m_gateway_ip; udp->DstPort = htons(NAT_TARGET_PORT);
                                    ip->Csum = 0; ip->Csum = checksum((USHORT*)ip, (ip->Ver_HLen & 0x0F) * 4);
                                    recalculate_udp_checksum(ip);
                                }
                                packets_to_mstcp.push_back(std::move(p));
                                intercepted = true;
                            }
                        }
                        if (!intercepted) packets_to_mstcp.push_back(std::move(p));
                    } else {
                        // --- 3. Outbound: Host to Client (RESTORE) ---
                        bool restored = false;
                        if (ip->SrcAddr == m_gateway_ip) {
                            if (ip->Proto == IPPROTO_TCP) {
                                PTCP_HEADER tcp = (PTCP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                if (ntohs(tcp->SrcPort) == NAT_TARGET_PORT) {
                                    ClientKey ck = { ip->DstAddr, tcp->DstPort };
                                    auto od = NatManager::instance().get_mapping(ck);
                                    if (od) {
                                        ip->SrcAddr = od->ip; tcp->SrcPort = od->port;
                                        ip->Csum = 0; ip->Csum = checksum((USHORT*)ip, (ip->Ver_HLen & 0x0F) * 4);
                                        recalculate_tcp_checksum(ip);
                                        packets_to_send.push_back(std::move(p));
                                        restored = true;
                                    }
                                }
                            } else if (ip->Proto == IPPROTO_UDP) {
                                PUDP_HEADER udp = (PUDP_HEADER)((char*)ip + (ip->Ver_HLen & 0x0F) * 4);
                                if (ntohs(udp->SrcPort) == NAT_TARGET_PORT) {
                                    ClientKey ck = { ip->DstAddr, udp->DstPort };
                                    auto od = NatManager::instance().get_mapping(ck);
                                    if (od) {
                                        ip->SrcAddr = od->ip; udp->SrcPort = od->port;
                                        ip->Csum = 0; ip->Csum = checksum((USHORT*)ip, (ip->Ver_HLen & 0x0F) * 4);
                                        recalculate_udp_checksum(ip);
                                        packets_to_send.push_back(std::move(p));
                                        restored = true;
                                    }
                                }
                            }
                        }
                        if (!restored) packets_to_send.push_back(std::move(p));
                    }
                } else { p.outbound ? packets_to_send.push_back(std::move(p)) : packets_to_mstcp.push_back(std::move(p)); }
            }
        }
        if (!packets_to_send.empty()) send_packets_to_adapter(std::move(packets_to_send));
        if (!packets_to_mstcp.empty()) { for (auto& p : packets_to_mstcp) send_to_mstcp((const char*)p.data->m_IBuffer, p.data->m_Length); }
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