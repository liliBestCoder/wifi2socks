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
    : m_adapter_handle(nullptr), m_wait_event(nullptr), m_running(false) {
}

WinPkFilterDriver::~WinPkFilterDriver() {
    stop();
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

bool WinPkFilterDriver::start(const std::string& adapter_name, PacketHandler handler) {
    LOG_INFO("[Driver] Initializing WinPkFilter on: %s", adapter_name.c_str());
    if (!m_ndis_api.IsDriverLoaded()) {
        LOG_ERROR("WinPkFilter driver not loaded.");
        return false;
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
    m_wait_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!m_ndis_api.SetPacketEvent(m_adapter_handle, m_wait_event)) return false;

    ADAPTER_MODE mode;
    mode.dwFlags = MSTCP_FLAG_SENT_RECEIVE | MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL;
    mode.hAdapterHandle = m_adapter_handle;
    if (!m_ndis_api.SetAdapterMode(&mode)) return false;

    m_running = true;
    m_worker_thread = std::thread(&WinPkFilterDriver::run, this);
    return true;
}

void WinPkFilterDriver::stop() {
    m_running = false;
    if (m_wait_event) SetEvent(m_wait_event);
    if (m_worker_thread.joinable()) m_worker_thread.join();
    if (m_adapter_handle) {
        ADAPTER_MODE mode = { m_adapter_handle, 0 };
        m_ndis_api.SetAdapterMode(&mode);
        m_ndis_api.SetPacketEvent(m_adapter_handle, nullptr);
        m_adapter_handle = nullptr;
    }
    if (m_wait_event) { CloseHandle(m_wait_event); m_wait_event = nullptr; }
}

void WinPkFilterDriver::run() {
    ETH_REQUEST request;
    auto buffer = std::make_unique<INTERMEDIATE_BUFFER>();
    request.hAdapterHandle = m_adapter_handle;
    request.EthPacket.Buffer = buffer.get();
    while (m_running) {
        WaitForSingleObject(m_wait_event, INFINITE);
        if (!m_running) break;
        while (m_ndis_api.ReadPacket(&request)) {
            bool outbound = (buffer->m_dwDeviceFlags == PACKET_FLAG_ON_SEND);
            if (m_packet_handler) m_packet_handler((const char*)buffer->m_IBuffer, buffer->m_Length, outbound);
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
    auto buffer = std::make_unique<INTERMEDIATE_BUFFER>();
    memset(buffer.get(), 0, sizeof(INTERMEDIATE_BUFFER));
    size_t clen = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(buffer->m_IBuffer, packet, clen);
    buffer->m_Length = (ULONG)clen;
    buffer->m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    ETH_REQUEST req = { m_adapter_handle, { buffer.get() } };
    return m_ndis_api.SendPacketToAdapter(&req) != FALSE;
}

bool WinPkFilterDriver::send_to_mstcp(const char* packet, size_t length) {
    if (!m_adapter_handle) return false;
    auto buffer = std::make_unique<INTERMEDIATE_BUFFER>();
    memset(buffer.get(), 0, sizeof(INTERMEDIATE_BUFFER));
    size_t clen = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(buffer->m_IBuffer, packet, clen);
    buffer->m_Length = (ULONG)clen;
    buffer->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    ETH_REQUEST req = { m_adapter_handle, { buffer.get() } };
    return m_ndis_api.SendPacketToMstcp(&req) != FALSE;
}
