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
#include "nat_manager.h" // Include the new NAT manager

// Define IP and TCP header structures for parsing
#include <pshpack1.h>
typedef struct _IP_HEADER
{
    UCHAR   Ver_HLen;       // IP version and header length
    UCHAR   TOS;            // Type of service
    USHORT  Len;            // Total length of the packet
    USHORT  ID;             // Unique identifier
    USHORT  Flags_Frag;     // Flags and fragment offset
    UCHAR   TTL;            // Time to live
    UCHAR   Proto;          // Protocol (TCP, UDP etc)
    USHORT  Csum;           // IP header checksum
    ULONG   SrcAddr;        // Source IP address
    ULONG   DstAddr;        // Destination IP address
} IP_HEADER, *PIP_HEADER;

typedef struct _TCP_HEADER
{
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

typedef struct _UDP_HEADER
{
    USHORT  SrcPort;
    USHORT  DstPort;
    USHORT  Len;
    USHORT  Csum;
} UDP_HEADER, *PUDP_HEADER;
#include <poppack.h>


#pragma comment(lib, "ndisapilib.lib")
#pragma comment(lib, "iphlpapi.lib")

// Global NAT Manager instance
static NatManager nat_manager;

// Define the NAT target address and port
const ULONG NAT_TARGET_IP = inet_addr("127.0.0.1");
const USHORT NAT_TARGET_PORT = 3080;


// Function to calculate TCP/UDP checksum
USHORT checksum(USHORT* buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if (size) {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

// Pseudo header for TCP/UDP checksum calculation
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

    // Zero out the checksum field
    tcp_header->Csum = 0;

    // Create pseudo-header
    PSEUDO_HEADER pseudo_header;
    pseudo_header.SrcAddr = ip_header->SrcAddr;
    pseudo_header.DstAddr = ip_header->DstAddr;
    pseudo_header.Zero = 0;
    pseudo_header.Proto = ip_header->Proto;
    pseudo_header.Len = htons((USHORT)tcp_len);

    // Allocate buffer for checksum calculation
    int total_len = sizeof(PSEUDO_HEADER) + tcp_len;
    // Align to 2 bytes
    if (total_len % 2 != 0) {
        total_len++;
    }
    char* checksum_buf = new char[total_len];
    memset(checksum_buf, 0, total_len);

    // Copy pseudo-header and TCP segment
    memcpy(checksum_buf, &pseudo_header, sizeof(PSEUDO_HEADER));
    memcpy(checksum_buf + sizeof(PSEUDO_HEADER), tcp_header, tcp_len);

    tcp_header->Csum = checksum((USHORT*)checksum_buf, total_len);

    delete[] checksum_buf;
    return tcp_header->Csum;
}


WinPkFilterDriver::WinPkFilterDriver()
    : m_adapter_handle(nullptr), m_wait_event(nullptr), m_running(false), m_tx_running(false) {
    // Increase driver internal pool size (RX-Ring equivalent) to 8192 packets
    // This is a static call that sets the global pool size for the driver.
    CNdisApi::SetPoolSize(8192);

    m_tx_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    // Allocate batch read request
    m_read_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    m_read_request->dwPacketsNumber = BATCH_SIZE;

    // Initialize read buffers array to nullptr
    for (int i = 0; i < BATCH_SIZE; ++i) {
        m_read_buffers[i] = nullptr;
    }

    // Allocate batch write request
    m_write_request = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + (BATCH_SIZE - 1) * sizeof(NDISRD_ETH_Packet));
    m_write_request->dwPacketsNumber = BATCH_SIZE;

    for (int i = 0; i < BATCH_SIZE; ++i) {
        m_write_buffers[i] = nullptr; 
    }

    m_send_buffer = new INTERMEDIATE_BUFFER();
}

WinPkFilterDriver::~WinPkFilterDriver() {
    stop();
    if (m_tx_event) CloseHandle(m_tx_event);

    // Return any remaining read buffers to the pool
    for (int i = 0; i < BATCH_SIZE; ++i) {
        if (m_read_buffers[i]) {
            PacketPool::instance().release(m_read_buffers[i]);
        }
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

bool WinPkFilterDriver::start(const std::string& adapter_name, PacketHandler handler, std::function<void()> on_before_batch, std::function<void()> on_after_batch) {
    LOG_INFO("[Driver] Initializing WinPkFilter on: %s", adapter_name.c_str());
    if (!m_ndis_api.IsDriverLoaded()) {
        LOG_ERROR("WinPkFilter driver not loaded.");
        return false;
    }

    // Pre-fill read buffers from pool for zero-copy
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
            LOG_INFO("[Driver] Matched adapter: %s (Handle: %p)", current_name.c_str(), m_adapter_handle);
            break;
        }
    }

    if (!found) {
        LOG_ERROR("[Driver] Could not find handle for adapter: %s", adapter_name.c_str());
        return false;
    }

    m_packet_handler = handler;
    m_on_before_batch = on_before_batch;
    m_on_after_batch = on_after_batch;
    m_batch_handler = nullptr;

    m_wait_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!m_ndis_api.SetPacketEvent(m_adapter_handle, m_wait_event)) return false;

    ADAPTER_MODE mode;
    mode.dwFlags = MSTCP_FLAG_SENT_RECEIVE | MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL;
    mode.hAdapterHandle = m_adapter_handle;
    if (!m_ndis_api.SetAdapterMode(&mode)) return false;

    m_running = true;
    m_tx_running = true;
    m_tx_thread = std::thread(&WinPkFilterDriver::tx_run, this);
    m_worker_thread = std::thread(&WinPkFilterDriver::run, this);
    return true;
}

bool WinPkFilterDriver::start_batch(const std::string& adapter_name, BatchPacketHandler handler) {
    LOG_INFO("[Driver] Initializing WinPkFilter (Batch Mode) on: %s", adapter_name.c_str());
    if (!m_ndis_api.IsDriverLoaded()) {
        LOG_ERROR("[Driver] WinPkFilter driver not loaded.");
        return false;
    }

    // Pre-fill read buffers from pool for zero-copy
    for (int i = 0; i < BATCH_SIZE; ++i) {
        if (!m_read_buffers[i]) {
            m_read_buffers[i] = PacketPool::instance().acquire();
            m_read_request->EthPacket[i].Buffer = m_read_buffers[i];
        }
    }

    TCP_AdapterList adapters;
    if (!m_ndis_api.GetTcpipBoundAdaptersInfo(&adapters)) {
        LOG_ERROR("[Driver] Failed to get adapters info.");
        return false;
    }

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
            LOG_INFO("[Driver] Matched adapter (Batch Mode): %s (Handle: %p)", current_name.c_str(), m_adapter_handle);
            break;
        }
    }

    if (!found) {
        LOG_ERROR("[Driver] Could not find handle for adapter: %s", adapter_name.c_str());
        return false;
    }

    m_packet_handler = nullptr;
    m_batch_handler = handler;
    m_on_before_batch = nullptr;
    m_on_after_batch = nullptr;

    m_wait_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!m_ndis_api.SetPacketEvent(m_adapter_handle, m_wait_event)) {
        LOG_ERROR("[Driver] Failed to set packet event.");
        return false;
    }

    ADAPTER_MODE mode;
    mode.dwFlags = MSTCP_FLAG_SENT_RECEIVE | MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL;
    mode.hAdapterHandle = m_adapter_handle;
    if (!m_ndis_api.SetAdapterMode(&mode)) {
        LOG_ERROR("[Driver] Failed to set adapter mode.");
        return false;
    }

    m_running = true;
    m_tx_running = true;
    m_tx_thread = std::thread(&WinPkFilterDriver::tx_run, this);
    m_worker_thread = std::thread(&WinPkFilterDriver::run, this);
    LOG_INFO("[Driver] Batch worker thread started.");
    return true;
}

void WinPkFilterDriver::stop() {
    m_running = false;
    m_tx_running = false;
    if (m_wait_event) SetEvent(m_wait_event);
    if (m_tx_event) SetEvent(m_tx_event);

    if (m_worker_thread.joinable()) m_worker_thread.join();
    if (m_tx_thread.joinable()) m_tx_thread.join();

    if (m_adapter_handle) {
        ADAPTER_MODE mode = { m_adapter_handle, 0 };
        m_ndis_api.SetAdapterMode(&mode);
        m_ndis_api.SetPacketEvent(m_adapter_handle, nullptr);
        m_adapter_handle = nullptr;
    }
    if (m_wait_event) { CloseHandle(m_wait_event); m_wait_event = nullptr; }
    m_on_before_batch = nullptr;
    m_on_after_batch = nullptr;
    m_batch_handler = nullptr;
}

void WinPkFilterDriver::tx_run() {
    while (m_tx_running) {
        WaitForSingleObject(m_tx_event, INFINITE);
        if (!m_tx_running) break;

        std::vector<std::vector<Packet>> local_queue;
        {
            std::lock_guard<std::mutex> lock(m_tx_mtx);
            local_queue.swap(m_tx_queue);
        }

        if (local_queue.empty()) continue;

        std::lock_guard<std::mutex> lock(m_write_mutex);
        m_write_request->hAdapterHandle = m_adapter_handle;

        for (auto& packets : local_queue) {
            size_t processed = 0;
            while (processed < packets.size()) {
                size_t current_batch = (std::min)(packets.size() - processed, (size_t)BATCH_SIZE);
                m_write_request->dwPacketsNumber = (DWORD)current_batch;
                m_write_request->dwPacketsSuccess = 0;

                for (size_t i = 0; i < current_batch; ++i) {
                    auto& p = packets[processed + i];
                    // Zero-copy: Point directly to the pooled buffer
                    m_write_request->EthPacket[i].Buffer = p.data.get();
                }

                m_ndis_api.SendPacketsToAdapter(m_write_request);
                processed += current_batch;
            }
        }
    }
}

void WinPkFilterDriver::run() {
    ETH_REQUEST single_request;
    single_request.hAdapterHandle = m_adapter_handle;

    m_read_request->hAdapterHandle = m_adapter_handle;

    // Get local IP address to distinguish packets from our app
    ULONG local_ip = inet_addr("127.0.0.1");


    while (m_running) {
        WaitForSingleObject(m_wait_event, INFINITE);
        if (!m_running) break;

        std::vector<Packet> packets_to_send;
        std::vector<Packet> packets_to_mstcp;

        bool has_packets = true;
        while (m_running && has_packets) {
            std::vector<Packet> captured_packets;
            captured_packets.reserve(BATCH_SIZE);

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
            }
            
            if (!captured_packets.empty()) {
                for (auto& p : captured_packets) {
                    char* buffer = (char*)p.data->m_IBuffer;
                    size_t length = p.data->m_Length;

                    if (length < 14) { // Not a full Ethernet frame
                        if (p.outbound) packets_to_send.push_back(std::move(p));
                        else packets_to_mstcp.push_back(std::move(p));
                        continue;
                    }
                    USHORT ether_type = ntohs(*(USHORT*)(buffer + 12));
                    if (ether_type != 0x0800) { // Not IP
                        if (p.outbound) packets_to_send.push_back(std::move(p));
                        else packets_to_mstcp.push_back(std::move(p));
                        continue;
                    }

                    PIP_HEADER ip_header = (PIP_HEADER)(buffer + 14);
                    
                    if (p.outbound) {
                        // Outbound: from protocol stack to adapter
                        // Two cases:
                        // 1. From our app (src=local) -> client (dst=remote_client). Needs Reverse NAT.
                        // 2. From client (src=remote_client) -> real server (dst=real_server). Needs Forward NAT.

                        if (ip_header->SrcAddr == local_ip) {
                            // Case 1: Reverse NAT for response from our local service
                            ClientKey client_key;
                            client_key.ip = ip_header->DstAddr;
                            
                            std::optional<OriginalDestination> orig_dest;

                            if (ip_header->Proto == IPPROTO_TCP) {
                                PTCP_HEADER tcp_header = (PTCP_HEADER)((char*)ip_header + (ip_header->Ver_HLen & 0x0F) * 4);
                                client_key.port = tcp_header->DstPort;
                                orig_dest = nat_manager.get_mapping(client_key);
                                if (orig_dest) {
                                    ip_header->SrcAddr = orig_dest->ip;
                                    tcp_header->SrcPort = orig_dest->port;
                                    
                                    ip_header->Csum = 0;
                                    ip_header->Csum = checksum((USHORT*)ip_header, (ip_header->Ver_HLen & 0x0F) * 4);
                                    tcp_header->Csum = 0;
                                    recalculate_tcp_checksum(ip_header);
                                }
                            } else if (ip_header->Proto == IPPROTO_UDP) {
                                 PUDP_HEADER udp_header = (PUDP_HEADER)((char*)ip_header + (ip_header->Ver_HLen & 0x0F) * 4);
                                 client_key.port = udp_header->DstPort;
                                 orig_dest = nat_manager.get_mapping(client_key);
                                 if (orig_dest) {
                                     ip_header->SrcAddr = orig_dest->ip;
                                     udp_header->SrcPort = orig_dest->port;

                                     ip_header->Csum = 0;
                                     ip_header->Csum = checksum((USHORT*)ip_header, (ip_header->Ver_HLen & 0x0F) * 4);
                                     udp_header->Csum = 0; // Optional for UDP
                                 }
                            }
                            // After modification, send to adapter
                            packets_to_send.push_back(std::move(p));

                        } else {
                            // Case 2: Forward NAT for initial packet from client
                            if (ip_header->Proto == IPPROTO_TCP || ip_header->Proto == IPPROTO_UDP) {
                                ClientKey key;
                                key.ip = ip_header->SrcAddr;
                                OriginalDestination dest;
                                dest.ip = ip_header->DstAddr;
                            
                                if (ip_header->Proto == IPPROTO_TCP) {
                                    PTCP_HEADER tcp_header = (PTCP_HEADER)((char*)ip_header + (ip_header->Ver_HLen & 0x0F) * 4);
                                    key.port = tcp_header->SrcPort;
                                    dest.port = tcp_header->DstPort;
                                    nat_manager.create_tcp_mapping(key, dest);

                                    ip_header->DstAddr = NAT_TARGET_IP;
                                    tcp_header->DstPort = htons(NAT_TARGET_PORT);

                                    ip_header->Csum = 0;
                                    ip_header->Csum = checksum((USHORT*)ip_header, (ip_header->Ver_HLen & 0x0F) * 4);
                                    tcp_header->Csum = 0;
                                    recalculate_tcp_checksum(ip_header);

                                } else { // UDP
                                    PUDP_HEADER udp_header = (PUDP_HEADER)((char*)ip_header + (ip_header->Ver_HLen & 0x0F) * 4);
                                    key.port = udp_header->SrcPort;
                                    dest.port = udp_header->DstPort;
                                    nat_manager.create_or_update_udp_mapping(key, dest);

                                    ip_header->DstAddr = NAT_TARGET_IP;
                                    udp_header->DstPort = htons(NAT_TARGET_PORT);

                                    ip_header->Csum = 0;
                                    ip_header->Csum = checksum((USHORT*)ip_header, (ip_header->Ver_HLen & 0x0F) * 4);
                                    udp_header->Csum = 0;
                                }
                                packets_to_mstcp.push_back(std::move(p));
                            } else {
                                packets_to_send.push_back(std::move(p));
                            }
                        }
                    } else { 
                        // Inbound: from adapter to protocol stack.
                        // Should be passed to mstcp directly in this architecture
                        // as Windows handles the inbound part of the TCP/IP connection.
                        packets_to_mstcp.push_back(std::move(p));
                    }
                }
            } else {
                has_packets = false;
            }
        }

        if (!packets_to_send.empty()) {
            send_packets_to_adapter(std::move(packets_to_send));
        }
        if (!packets_to_mstcp.empty()) {
            for (auto& p : packets_to_mstcp) {
                 send_to_mstcp((const char*)p.data->m_IBuffer, p.data->m_Length);
            }
        }
    }
}

bool WinPkFilterDriver::get_adapter_mac(const std::string& adapter_name, uint8_t* mac) {
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    ULONG outBufLen = 15000;
    pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if (!pAddresses) return false;
    
    std::string guid = adapter_name;
    size_t pos = guid.find("{");
    if (pos != std::string::npos) guid = guid.substr(pos);

    if (GetAdaptersAddresses(AF_INET, 0, nullptr, pAddresses, &outBufLen) == ERROR_SUCCESS) {
        for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != nullptr; pCurr = pCurr->Next) {
            std::string name = pCurr->AdapterName;
            if (guid.find(name) != std::string::npos) {
                if (pCurr->PhysicalAddressLength == 6) {
                    memcpy(mac, pCurr->PhysicalAddress, 6);
                    LOG_INFO("[Driver] Found MAC for %s: %02X:%02X:%02X:%02X:%02X:%02X", name.c_str(), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    free(pAddresses); return true;
                }
            }
        }
    }
    if (pAddresses) free(pAddresses);
    return false;
}

bool WinPkFilterDriver::send_to_adapter(const char* packet, size_t length) {
    if (!m_adapter_handle) return false;
    
    std::lock_guard<std::mutex> lock(m_send_mutex);
    size_t clen = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(m_send_buffer->m_IBuffer, packet, clen);
    m_send_buffer->m_Length = (ULONG)clen;
    m_send_buffer->m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    
    ETH_REQUEST req = { m_adapter_handle, { m_send_buffer } };
    return m_ndis_api.SendPacketToAdapter(&req) != FALSE;
}

bool WinPkFilterDriver::send_packets_to_adapter(std::vector<Packet>&& packets) {
    if (!m_adapter_handle || packets.empty()) return false;

    {
        std::lock_guard<std::mutex> lock(m_tx_mtx);
        m_tx_queue.push_back(std::move(packets));
    }
    SetEvent(m_tx_event);
    return true;
}

bool WinPkFilterDriver::send_to_mstcp(const char* packet, size_t length) {
    if (!m_adapter_handle) return false;

    std::lock_guard<std::mutex> lock(m_send_mutex);
    size_t clen = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(m_send_buffer->m_IBuffer, packet, clen);
    m_send_buffer->m_Length = (ULONG)clen;
    m_send_buffer->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    
    ETH_REQUEST req = { m_adapter_handle, { m_send_buffer } };
    return m_ndis_api.SendPacketToMstcp(&req) != FALSE;
}