#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <algorithm>
#include <iostream>
#include <vector>
#include "adapter.h"

#pragma comment(lib, "iphlpapi.lib")

std::vector<AdapterInfo> get_wifi_direct_adapters() {
    std::vector<AdapterInfo> adapters;
    ULONG bufferSize = 15000;
    std::vector<BYTE> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES* pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    ULONG status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &bufferSize);
    if (status == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &bufferSize);
    }

    if (status != NO_ERROR)
        return adapters;

    std::wstring prefix = L"Microsoft Wi-Fi Direct Virtual Adapter";

    for (auto pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
        if (!pCurr->Description) continue;

        std::wstring desc = pCurr->Description;
        if (desc.find(prefix) != std::wstring::npos) {
            AdapterInfo info;
            info.guid_name = pCurr->AdapterName ? "\\DEVICE\\" + std::string(pCurr->AdapterName) : "";
            info.luid = pCurr->Luid;
            info.description = desc;
            info.index = 0;

            // Extract number from description if present
            // Matches "Microsoft Wi-Fi Direct Virtual Adapter #3"
            size_t hashPos = desc.find(L"#");
            if (hashPos != std::wstring::npos) {
                try {
                    info.index = std::stoi(desc.substr(hashPos + 1));
                } catch (...) {
                    info.index = 0;
                }
            }

            adapters.push_back(info);
        }
    }

    // Sort by index descending (highest number first)
    // Then sort by description string for consistency
    std::sort(adapters.begin(), adapters.end(), [](const AdapterInfo& a, const AdapterInfo& b) {
        if (a.index != b.index) return a.index > b.index;
        return a.description > b.description;
    });

    return adapters;
}

std::string find_best_wifi_direct_adapter() {
    auto adapters = get_wifi_direct_adapters();
    if (adapters.empty()) return "";
    return adapters[0].guid_name;
}
