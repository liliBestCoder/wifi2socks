#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <algorithm>
#include <climits>
#include <cwctype>
#include <iostream>
#include <vector>
#include <string>
#include "adapter.h"

#pragma comment(lib, "iphlpapi.lib")

static std::wstring to_lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)tolower(c); });
    return s;
}

static std::wstring widen_ascii(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

static bool contains_any(const std::wstring& text, const std::vector<std::wstring>& needles) {
    for (const auto& n : needles) {
        if (text.find(n) != std::wstring::npos) return true;
    }
    return false;
}

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
            info.friendly_name = pCurr->FriendlyName ? pCurr->FriendlyName : L"";
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

std::vector<AdapterInfo> get_ethernet_adapters(const std::string& hint) {
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
    if (status != NO_ERROR) return adapters;

    std::wstring hint_w = to_lower(widen_ascii(hint));
    const std::vector<std::wstring> excluded = {
        L"wi-fi", L"wifi", L"wireless", L"wi-fi direct", L"virtual", L"vpn", L"tunnel",
        L"anyconnect", L"sangfor", L"atrust", L"openvpn", L"bluetooth", L"loopback"
    };

    for (auto pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
        if (!pCurr->AdapterName || !pCurr->Description) continue;
        if (pCurr->IfType != IF_TYPE_ETHERNET_CSMACD) continue;
        if (pCurr->OperStatus != IfOperStatusUp) continue;

        std::wstring desc = pCurr->Description ? pCurr->Description : L"";
        std::wstring friendly = pCurr->FriendlyName ? pCurr->FriendlyName : L"";
        std::wstring haystack = to_lower(desc + L" " + friendly + L" " + widen_ascii(pCurr->AdapterName));

        if (!hint_w.empty() && haystack.find(hint_w) == std::wstring::npos) {
            continue;
        }
        if (hint_w.empty() && contains_any(haystack, excluded)) {
            continue;
        }

        AdapterInfo info;
        info.guid_name = "\\DEVICE\\" + std::string(pCurr->AdapterName);
        info.luid = pCurr->Luid;
        info.friendly_name = friendly;
        info.description = desc;
        info.index = (pCurr->Ipv4Metric > 0 && pCurr->Ipv4Metric < INT_MAX) ? (int)pCurr->Ipv4Metric : INT_MAX;
        adapters.push_back(info);
    }

    std::sort(adapters.begin(), adapters.end(), [](const AdapterInfo& a, const AdapterInfo& b) {
        if (a.index != b.index) return a.index < b.index;
        return a.description < b.description;
    });
    return adapters;
}

std::string find_best_ethernet_adapter(const std::string& hint) {
    auto adapters = get_ethernet_adapters(hint);
    if (adapters.empty()) return "";
    return adapters[0].guid_name;
}

bool ensure_adapter_ipv4(const NET_LUID& luid, const std::string& ip, uint8_t prefix_len) {
    IN_ADDR addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;

    PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
    if (GetUnicastIpAddressTable(AF_INET, &table) == NO_ERROR && table) {
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            auto& row = table->Table[i];
            if (row.InterfaceLuid.Value == luid.Value && row.Address.Ipv4.sin_addr.S_un.S_addr == addr.S_un.S_addr) {
                FreeMibTable(table);
                return true;
            }
        }
        FreeMibTable(table);
    }

    MIB_UNICASTIPADDRESS_ROW row{};
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = luid;
    row.Address.si_family = AF_INET;
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr = addr;
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = IpDadStatePreferred;
    DWORD ret = CreateUnicastIpAddressEntry(&row);
    return ret == NO_ERROR || ret == ERROR_OBJECT_ALREADY_EXISTS;
}

bool remove_adapter_ipv4(const NET_LUID& luid, const std::string& ip) {
    IN_ADDR addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;

    PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
    if (GetUnicastIpAddressTable(AF_INET, &table) != NO_ERROR || !table) return false;

    bool removed = false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        auto row = table->Table[i];
        if (row.InterfaceLuid.Value == luid.Value && row.Address.Ipv4.sin_addr.S_un.S_addr == addr.S_un.S_addr) {
            removed = DeleteUnicastIpAddressEntry(&row) == NO_ERROR || removed;
        }
    }
    FreeMibTable(table);
    return removed;
}
