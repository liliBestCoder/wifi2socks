#include "winpkfilter_driver.h"
#include "logger.h"
#include <iostream>

#pragma comment(lib, "ndisapilib.lib")

WinPkFilterDriver::WinPkFilterDriver()
    : m_adapter_handle(nullptr), m_wait_event(nullptr), m_running(false) {
}

WinPkFilterDriver::~WinPkFilterDriver() {
    stop();
}

std::vector<std::pair<std::string, std::string>> WinPkFilterDriver::get_adapters() {
    std::vector<std::pair<std::string, std::string>> result;
    CNdisApi api;
    if (!api.IsDriverLoaded()) {
        return result;
    }

    TCP_AdapterList adapters;
    if (api.GetTcpipBoundAdaptersInfo(&adapters)) {
        for (UINT i = 0; i < adapters.m_nAdapterCount; ++i) {
            // Note: Common.h uses m_szAdapterNameList
            result.push_back({ (char*)adapters.m_szAdapterNameList[i], (char*)adapters.m_szAdapterNameList[i] });
        }
    }
    return result;
}

bool WinPkFilterDriver::start(const std::string& adapter_name, PacketHandler handler) {
    if (!m_ndis_api.IsDriverLoaded()) {
        LOG_ERROR("WinPkFilter driver not loaded.");
        return false;
    }

    TCP_AdapterList adapters;
    if (!m_ndis_api.GetTcpipBoundAdaptersInfo(&adapters)) {
        LOG_ERROR("Failed to get adapter list.");
        return false;
    }

    bool found = false;
    for (UINT i = 0; i < adapters.m_nAdapterCount; ++i) {
        if (adapter_name == (char*)adapters.m_szAdapterNameList[i]) {
            m_adapter_handle = adapters.m_nAdapterHandle[i];
            found = true;
            break;
        }
    }

    if (!found) {
        LOG_ERROR("Target adapter not found: %s", adapter_name.c_str());
        return false;
    }

    m_packet_handler = handler;
    m_wait_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!m_wait_event) {
        LOG_ERROR("Failed to create wait event.");
        return false;
    }

    if (!m_ndis_api.SetPacketEvent(m_adapter_handle, m_wait_event)) {
        LOG_ERROR("Failed to set packet event.");
        return false;
    }

    ADAPTER_MODE mode;
    mode.dwFlags = MSTCP_FLAG_SENT_RECEIVE | MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL;
    mode.hAdapterHandle = m_adapter_handle;
    if (!m_ndis_api.SetAdapterMode(&mode)) {
        LOG_ERROR("Failed to set adapter mode.");
        return false;
    }

    m_running = true;
    m_worker_thread = std::thread(&WinPkFilterDriver::run, this);

    LOG_INFO("WinPkFilter driver started on adapter: %s", adapter_name.c_str());
    return true;
}

void WinPkFilterDriver::stop() {
    m_running = false;
    if (m_wait_event) {
        SetEvent(m_wait_event);
    }
    if (m_worker_thread.joinable()) {
        m_worker_thread.join();
    }

    if (m_adapter_handle) {
        ADAPTER_MODE mode;
        mode.dwFlags = 0; 
        mode.hAdapterHandle = m_adapter_handle;
        m_ndis_api.SetAdapterMode(&mode);
        m_ndis_api.SetPacketEvent(m_adapter_handle, nullptr);
        m_adapter_handle = nullptr;
    }

    if (m_wait_event) {
        CloseHandle(m_wait_event);
        m_wait_event = nullptr;
    }
}

void WinPkFilterDriver::run() {
    ETH_REQUEST request;
    INTERMEDIATE_BUFFER buffer;
    request.hAdapterHandle = m_adapter_handle;
    request.EthPacket.Buffer = &buffer;

    while (m_running) {
        WaitForSingleObject(m_wait_event, INFINITE);
        if (!m_running) break;

        while (m_ndis_api.ReadPacket(&request)) {
            bool outbound = (buffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND);
            if (m_packet_handler) {
                m_packet_handler((const char*)buffer.m_IBuffer, buffer.m_Length, outbound);
            }
        }
    }
}

bool WinPkFilterDriver::get_adapter_mac(const std::string& adapter_name, uint8_t* mac) {
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    ULONG outBufLen = 15000;
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    
    std::string guid = adapter_name;
    size_t pos = guid.find("{");
    if (pos != std::string::npos) {
        guid = guid.substr(pos);
    }

    if (GetAdaptersAddresses(AF_INET, 0, nullptr, pAddresses, &outBufLen) == ERROR_SUCCESS) {
        for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses != nullptr; pCurrAddresses = pCurrAddresses->Next) {
            std::string current_name = pCurrAddresses->AdapterName;
            if (guid.find(current_name) != std::string::npos) {
                if (pCurrAddresses->PhysicalAddressLength == 6) {
                    memcpy(mac, pCurrAddresses->PhysicalAddress, 6);
                    free(pAddresses);
                    return true;
                }
            }
        }
    }
    if (pAddresses) free(pAddresses);
    return false;
}

bool WinPkFilterDriver::send_to_adapter(const char* packet, size_t length) {
    if (!m_adapter_handle) return false;

    INTERMEDIATE_BUFFER buffer;
    memset(&buffer, 0, sizeof(buffer));
    length = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(buffer.m_IBuffer, packet, length);
    buffer.m_Length = (ULONG)length;
    buffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;

    ETH_REQUEST request;
    request.hAdapterHandle = m_adapter_handle;
    request.EthPacket.Buffer = &buffer;

    return m_ndis_api.SendPacketToAdapter(&request) != FALSE;
}

bool WinPkFilterDriver::send_to_mstcp(const char* packet, size_t length) {
    if (!m_adapter_handle) return false;

    INTERMEDIATE_BUFFER buffer;
    memset(&buffer, 0, sizeof(buffer));
    length = (length > MAX_ETHER_FRAME) ? MAX_ETHER_FRAME : length;
    memcpy(buffer.m_IBuffer, packet, length);
    buffer.m_Length = (ULONG)length;
    buffer.m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;

    ETH_REQUEST request;
    request.hAdapterHandle = m_adapter_handle;
    request.EthPacket.Buffer = &buffer;

    return m_ndis_api.SendPacketToMstcp(&request) != FALSE;
}