#pragma once

#include <string>
#include <vector>
#include <winsock2.h>
#include <iphlpapi.h>

struct AdapterInfo {
    std::string guid_name;    // \DEVICE\{GUID}
    NET_LUID luid;
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
