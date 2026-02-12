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

#pragma comment(lib, "ndisapilib.lib")
#pragma comment(lib, "iphlpapi.lib")

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

    while (m_running) {
        WaitForSingleObject(m_wait_event, INFINITE);
        if (!m_running) break;

        bool has_packets = true;
        while (m_running && has_packets) {
            std::vector<Packet> packets;
            packets.reserve(BATCH_SIZE);

            // 1. Try batch read
            m_read_request->dwPacketsNumber = BATCH_SIZE;
            m_read_request->dwPacketsSuccess = 0;
            
            if (m_ndis_api.ReadPackets(m_read_request) && m_read_request->dwPacketsSuccess > 0) {
                for (unsigned int i = 0; i < m_read_request->dwPacketsSuccess; ++i) {
                    PINTERMEDIATE_BUFFER filled_buf = m_read_request->EthPacket[i].Buffer;
                    bool outbound = (filled_buf->m_dwDeviceFlags == PACKET_FLAG_ON_SEND);
                    
                    // Zero-copy: Transfer buffer to Packet object
                    packets.push_back({ RawPacketPtr(filled_buf), outbound });
                    
                    // Replace the "loaned" buffer with a new one from the pool
                    m_read_buffers[i] = PacketPool::instance().acquire();
                    m_read_request->EthPacket[i].Buffer = m_read_buffers[i];
                }
            } else {
                // 2. Fallback to single packet reads
                // Reuse the first buffer slot for single reads
                single_request.EthPacket.Buffer = m_read_buffers[0];
                while (packets.size() < BATCH_SIZE && m_ndis_api.ReadPacket(&single_request)) {
                    PINTERMEDIATE_BUFFER filled_buf = single_request.EthPacket.Buffer;
                    bool outbound = (filled_buf->m_dwDeviceFlags == PACKET_FLAG_ON_SEND);
                    
                    packets.push_back({ RawPacketPtr(filled_buf), outbound });
                    
                    // Replace the buffer
                    m_read_buffers[0] = PacketPool::instance().acquire();
                    single_request.EthPacket.Buffer = m_read_buffers[0];
                    m_read_request->EthPacket[0].Buffer = m_read_buffers[0]; // Keep batch request in sync
                }
            }

            if (!packets.empty()) {
                if (m_batch_handler) {
                    m_batch_handler(std::move(packets));
                } else {
                    if (m_on_before_batch) m_on_before_batch();
                    for (const auto& p : packets) {
                        if (m_packet_handler) m_packet_handler((const char*)p.data->m_IBuffer, p.data->m_Length, p.outbound);
                    }
                    if (m_on_after_batch) m_on_after_batch();
                }
            } else {
                has_packets = false;
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