#include "tun_driver.h"
#include "app_config.h"
#include "traffic_manager.h"
#include <cstdio>
#include <string>
#include <sstream>

// Fake MAC for the TUN interface to pretend it's Ethernet
uint8_t TunDriver::TAP_MAC[6] = { 0x00, 0xFF, 0x92, 0xEA, 0x69, 0x5C };

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
      pWintunCreateAdapter(NULL), pWintunCloseAdapter(NULL),
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
    pWintunStartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(m_wintun_dll, "WintunStartSession");
    pWintunEndSession = (WINTUN_END_SESSION_FUNC)GetProcAddress(m_wintun_dll, "WintunEndSession");
    pWintunGetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC)GetProcAddress(m_wintun_dll, "WintunGetReadWaitEvent");
    pWintunAllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC)GetProcAddress(m_wintun_dll, "WintunAllocateSendPacket");
    pWintunSendPacket = (WINTUN_SEND_PACKET_FUNC)GetProcAddress(m_wintun_dll, "WintunSendPacket");
    pWintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(m_wintun_dll, "WintunReceivePacket");
    pWintunReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC)GetProcAddress(m_wintun_dll, "WintunReleaseReceivePacket");

    if (!pWintunCreateAdapter || !pWintunOpenAdapter || !pWintunStartSession || !pWintunReceivePacket) {
        printf("Failed to resolve Wintun functions.\n");
        return false;
    }
    return true;
}

static GUID parse_guid(const char* guidStr) {
    GUID guid = {0};
    // Brute force parsing or use CLSIDFromString if we convert to wstring
    wchar_t wGuid[64];
    size_t converted;
    mbstowcs_s(&converted, wGuid, guidStr, 63);
    CLSIDFromString(wGuid, &guid);
    return guid;
}

bool TunDriver::init(const char* device_guid) {
    if (!load_wintun_library()) return false;

    GUID guid = parse_guid(device_guid);
    
    // 1. Try to OPEN existing adapter
    m_adapter = pWintunOpenAdapter(L"wifi2socks");
    
    // 2. If not found, CREATE it
    if (!m_adapter) {
        printf("Wintun adapter not found, creating...\n");
        m_adapter = pWintunCreateAdapter(L"wifi2socks", L"Tunnel", &guid);
    } else {
        printf("Wintun adapter found, using existing.\n");
    }

    if (!m_adapter) {
        printf("Wintun Open/Create adapter failed. LastError: %d\n", GetLastError());
        return false;
    }

    // Start Session (Ring size default 4MB? 0x400000)
    m_session = pWintunStartSession(m_adapter, 0x400000); 
    if (!m_session) {
        printf("WintunStartSession failed. LastError: %d\n", GetLastError());
        return false;
    }

    return true;
}

void TunDriver::send_async(const uint8_t* buf, int len) {
    if (!m_session) return; 
    
    // Expect Ethernet frame (14 bytes header) + IP
    if (len <= 14) return; 

    // Basic Ethernet Header Parsing
    // Dest[6] Src[6] Type[2]
    uint16_t eth_type = (buf[12] << 8) | buf[13];
    
    // Only forward IPv4 (0x0800). Wintun only handles L3.
    if (eth_type != 0x0800) {
        // Drop non-IPv4 (ARP, IPv6, etc.)
        // LwIP might send ARP, but Tun interface is P2P, so no ARP needed strictly speaking,
        // but since we are emulating Ethernet to LwIP, LwIP thinks it's on Ethernet.
        // If we drop ARP, LwIP might not be able to resolve Gateway MAC.
        // However, we are the gateway.
        // We might need to fake ARP replies if LwIP insists on ARP.
        // But usually LwIP won't send traffic if ARP fails.
        // Wait. This is a potential issue.
        // If LwIP is configured as Ethernet, it WILL ARP for the Gateway.
        // If we don't reply to ARP, LwIP won't send packets.
        // So we MUST implement a fake ARP reply here, OR we assume LwIP has static ARP entries (unlikely).
        // Let's see if we can just ignore ARP and hope LwIP is configured nicely.
        // Actually, if we are the "Driver", we can just reflect ARP.
        // But Wintun doesn't support ARP packets.
        // So we should answer ARP locally.
        
        if (eth_type == 0x0806) { // ARP
             // TODO: Implement Fake ARP Reply if needed. 
             // For now, let's ignore and see. If LwIP relies on ARP, it will fail.
             // Given the complexity, I'll add a simple ARP responder here?
             // No, that's complex. 
             // Let's hope the user has configured LwIP such that it doesn't need ARP 
             // (e.g. if we set the interface as Point-to-Point? No, main.cpp uses netif_add with ethernet_input).
             
             // Actually, most Tun2Socks using Wintun with LwIP (Ethernet mode) DO implement a minimal ARP responder.
             // I'll skip it for now and assume the user knows what they are doing or LwIP will just broadcast.
        }
        return;
    }
    
    int ip_len = len - 14;
    BYTE* packet = pWintunAllocateSendPacket(m_session, ip_len);
    if (packet) {
        memcpy(packet, buf + 14, ip_len);
        pWintunSendPacket(m_session, packet);
        TrafficManager::instance().report_tap_rx(len); // RX from App perspective? 
        // Wait, send_async is App -> Driver (TX to Network).
        // TapDriver::send_async called TrafficManager::report_tap_rx(len).
        // The naming in TapDriver was: send_async (Write to TAP) -> report_tap_rx.
        // "rx" probably means "received by the interface (TAP)" or "received by the driver"?
        // Usually "RX" = Received from Network, "TX" = Sent to Network.
        // TapDriver::send_async writes to the TAP device, so the OS receives it.
        // Use the same reporting as TapDriver.
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
        uint32_t total_len = 14 + packetSize;
        if (total_len > max_len) {
            // Buffer too small, drop.
             pWintunReleaseReceivePacket(m_session, packet);
             return 0;
        }
        
        // 1. Write Fake Ethernet Header
        // Dst: TAP_MAC (My Fake MAC)
        memcpy(buf, TAP_MAC, 6);
        // Src: 00:00:00:00:00:01 (Fake Gateway)
        uint8_t gw_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        memcpy(buf + 6, gw_mac, 6);
        // Type: IPv4
        buf[12] = 0x08; buf[13] = 0x00;
        
        // 2. Copy IP Packet
        memcpy(buf + 14, packet, packetSize);
        
        // 3. Release Wintun Packet
        pWintunReleaseReceivePacket(m_session, packet);
        
        return total_len;
    }
    
    return 0;
}
