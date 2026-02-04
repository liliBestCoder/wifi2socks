#include "tun_driver.h"
#include "app_config.h"
#include "traffic_manager.h"
#include <cstdio>
#include <string>
#include <sstream>
#include <objbase.h>
#include <winsock2.h>
#include <ws2tcpip.h>
// Fix for netioapi.h compilation error regarding NTSTATUS
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#include <iphlpapi.h>
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

// Fake MAC for the TUN interface to pretend it's Ethernet
uint8_t TunDriver::TAP_MAC[6] = { 0x00, 0xFF, 0x92, 0xea, 0x69, 0x5c };

static void parse_mac(const std::string& str, uint8_t* mac) {
    unsigned int bytes[6];
    if (sscanf_s(str.c_str(), "%x:%x:%x:%x:%x:%x", 
        &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) == 6) {
        for (int i=0; i<6; ++i) mac[i] = (uint8_t)bytes[i];
    }
}

TunDriver& TunDriver::instance() {
    static TunDriver inst;
    return inst;
}

TunDriver::TunDriver() 
    : m_wintun_dll(NULL), m_adapter(NULL), m_session(NULL),
      pWintunCreateAdapter(NULL), pWintunCloseAdapter(NULL), pWintunGetAdapterLUID(NULL),
      pWintunStartSession(NULL), pWintunEndSession(NULL),
      pWintunGetReadWaitEvent(NULL), pWintunAllocateSendPacket(NULL),
      pWintunSendPacket(NULL), pWintunReceivePacket(NULL),
      pWintunReleaseReceivePacket(NULL) {
    parse_mac(g_config.tap_mac, TAP_MAC);
}

TunDriver::~TunDriver() {
    if (pWintunEndSession && m_session) {
        pWintunEndSession(m_session);
    }
    if (pWintunCloseAdapter && m_adapter) {
        pWintunCloseAdapter(m_adapter);
    }
    if (m_wintun_dll) {
        FreeLibrary(m_wintun_dll);
    }
}

bool TunDriver::load_wintun_library() {
    m_wintun_dll = LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!m_wintun_dll) {
        printf("Failed to load wintun.dll\n");
        return false;
    }

    pWintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(m_wintun_dll, "WintunCreateAdapter");
    pWintunOpenAdapter = (WINTUN_OPEN_ADAPTER_FUNC)GetProcAddress(m_wintun_dll, "WintunOpenAdapter");
    pWintunCloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC)GetProcAddress(m_wintun_dll, "WintunCloseAdapter");
    pWintunGetAdapterLUID = (WINTUN_GET_ADAPTER_LUID_FUNC)GetProcAddress(m_wintun_dll, "WintunGetAdapterLUID");
    pWintunStartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(m_wintun_dll, "WintunStartSession");
    pWintunEndSession = (WINTUN_END_SESSION_FUNC)GetProcAddress(m_wintun_dll, "WintunEndSession");
    pWintunGetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC)GetProcAddress(m_wintun_dll, "WintunGetReadWaitEvent");
    pWintunAllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC)GetProcAddress(m_wintun_dll, "WintunAllocateSendPacket");
    pWintunSendPacket = (WINTUN_SEND_PACKET_FUNC)GetProcAddress(m_wintun_dll, "WintunSendPacket");
    pWintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(m_wintun_dll, "WintunReceivePacket");
    pWintunReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC)GetProcAddress(m_wintun_dll, "WintunReleaseReceivePacket");

    if (!pWintunCreateAdapter || !pWintunOpenAdapter || !pWintunStartSession || !pWintunReceivePacket || !pWintunGetAdapterLUID) {
        printf("Failed to resolve Wintun functions.\n");
        return false;
    }
    return true;
}

static GUID parse_guid(const char* guidStr) {
    GUID guid = {0};
    wchar_t wGuid[64];
    size_t converted;
    mbstowcs_s(&converted, wGuid, guidStr, 63);
    CLSIDFromString(wGuid, &guid);
    return guid;
}

bool TunDriver::init(const char* device_guid) {
    if (!load_wintun_library()) return false;

    GUID guid = parse_guid(device_guid);
    
    // Prioritize CreateAdapter: It will open the existing one if Name and GUID match.
    m_adapter = pWintunCreateAdapter(L"wifi2socks", L"Tunnel", &guid);
    
    if (!m_adapter) {
        DWORD err = GetLastError();
        if (err == ERROR_ALREADY_EXISTS) {
            // Name exists but GUID might differ or other collision, try direct Open.
            m_adapter = pWintunOpenAdapter(L"wifi2socks");
        }
    }

    if (!m_adapter) {
        printf("Wintun Open/Create adapter failed. LastError: %d\n", GetLastError());
        return false;
    }

    printf("Wintun adapter is ready.\n");

    // Start Session (Ring size default 4MB? 0x400000) 
    m_session = pWintunStartSession(m_adapter, 0x400000); 
    if (!m_session) {
        printf("WintunStartSession failed. LastError: %d\n", GetLastError());
        return false;
    }

    return true;
}

static uint8_t count_set_bits(uint32_t n) {
    uint8_t count = 0;
    while (n > 0) {
        n &= (n - 1);
        count++;
    }
    return count;
}

bool TunDriver::set_ip(const char* ip, const char* mask, const char* gateway) {
    if (!m_adapter) return false;

    LUID luid = { 0 };
    pWintunGetAdapterLUID(m_adapter, &luid);

    // 1. Parse IP
    MIB_UNICASTIPADDRESS_ROW ipRow;
    InitializeUnicastIpAddressEntry(&ipRow);
    ipRow.InterfaceLuid.Value = ((ULONG64)luid.HighPart << 32) | luid.LowPart;
    ipRow.Address.si_family = AF_INET;
    
    if (inet_pton(AF_INET, ip, &ipRow.Address.Ipv4.sin_addr) != 1) {
        printf("Invalid IP address: %s\n", ip);
        return false;
    }

    // 2. Parse Mask to PrefixLength
    struct in_addr maskAddr;
    if (inet_pton(AF_INET, mask, &maskAddr) != 1) {
        printf("Invalid Subnet Mask: %s\n", mask);
        return false;
    }
    ipRow.OnLinkPrefixLength = count_set_bits(ntohl(maskAddr.s_addr));
    ipRow.DadState = IpDadStatePreferred;

    // 3. Create Unicast IP Entry
    DWORD err = CreateUnicastIpAddressEntry(&ipRow);
    if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
        printf("CreateUnicastIpAddressEntry failed: %d\n", err);
        return false;
    }

    // 4. Set Gateway (Default Route) if provided
    if (gateway && strlen(gateway) > 0) {
        MIB_IPFORWARD_ROW2 routeRow;
        InitializeIpForwardEntry(&routeRow);
        routeRow.InterfaceLuid.Value = ((ULONG64)luid.HighPart << 32) | luid.LowPart;
        routeRow.DestinationPrefix.Prefix.si_family = AF_INET;
        routeRow.DestinationPrefix.PrefixLength = 0; // 0.0.0.0/0
        routeRow.NextHop.si_family = AF_INET;
        
        if (inet_pton(AF_INET, gateway, &routeRow.NextHop.Ipv4.sin_addr) != 1) {
            printf("Invalid Gateway: %s\n", gateway);
            return false;
        }
        
        routeRow.Metric = 60;
        routeRow.Protocol = MIB_IPPROTO_NETMGMT;
        
        err = CreateIpForwardEntry2(&routeRow);
        if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
            printf("CreateIpForwardEntry2 (Gateway) failed: %d\n", err); // Don't fail the whole setup if route fails, maybe it exists
        }
    }

    printf("Wintun Interface Configured: IP=%s Mask=%s Gateway=%s\n", ip, mask, gateway ? gateway : "None");
    return true;
}

void TunDriver::send_async(const uint8_t* buf, int len) {
    if (!m_session) return; 
    
    if (len < 20) return; // Minimum IP packet size

    // Directly allocate and send IP packet
    BYTE* packet = pWintunAllocateSendPacket(m_session, len);
    if (packet) {
        memcpy(packet, buf, len);
        pWintunSendPacket(m_session, packet);
        TrafficManager::instance().report_tap_rx(len); 
    }
}

HANDLE TunDriver::get_read_wait_event() {
    if (!m_session) return NULL;
    return pWintunGetReadWaitEvent(m_session);
}

uint32_t TunDriver::read(uint8_t* buf, uint32_t max_len) {
    if (!m_session) return 0;
    
    DWORD packetSize = 0;
    BYTE* packet = pWintunReceivePacket(m_session, &packetSize);
    
    if (packet) {
        if (packetSize > max_len) {
             pWintunReleaseReceivePacket(m_session, packet);
             return 0;
        }
        
        // Directly copy IP Packet without adding fake Ethernet Header
        memcpy(buf, packet, packetSize);
        
        // Release Wintun Packet
        pWintunReleaseReceivePacket(m_session, packet);
        
        return packetSize;
    }
    
    return 0;
}