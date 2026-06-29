#pragma once

#include <string>
#include <vector>
#include <winsock2.h>
#include <iphlpapi.h>

struct AdapterInfo {
    std::string guid_name;    // \DEVICE\{GUID}
    NET_LUID luid;
    std::wstring friendly_name;
    std::wstring description;
    int index;                // Suffix number if any (e.g., 3 for "#3", 0 for no suffix)
};

/**
 * @brief Finds all Microsoft Wi-Fi Direct Virtual Adapters and returns them sorted by suffix index descending.
 */
std::vector<AdapterInfo> get_wifi_direct_adapters();

/**
 * @brief Returns the best adapter name (e.g., \DEVICE\{GUID}) or empty string if not found.
 */
std::string find_best_wifi_direct_adapter();

/**
 * @brief Finds physical Ethernet adapters, excluding common VPN/tunnel/virtual adapters.
 */
std::vector<AdapterInfo> get_ethernet_adapters(const std::string& hint = "");

/**
 * @brief Returns the best physical Ethernet adapter name (e.g., \DEVICE\{GUID}) or empty string.
 */
std::string find_best_ethernet_adapter(const std::string& hint = "");

bool ensure_adapter_ipv4(const NET_LUID& luid, const std::string& ip, uint8_t prefix_len);
bool remove_adapter_ipv4(const NET_LUID& luid, const std::string& ip);
