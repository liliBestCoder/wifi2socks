#include "ics_manager.h"
#include <iostream>
#include <vector>
// #include <hnetcfg.h> // Removed to avoid missing file error

using namespace Microsoft::WRL;

// Check if CLSID_NetSharingManager is defined
const CLSID CLSID_NetSharingManager = { 0x5C63C1AD, 0x3956, 0x4FF8, { 0x84, 0x86, 0x40, 0x03, 0x47, 0x58, 0x31, 0x5B } };

bool IcsManager::EnableICS(const std::wstring& publicAdapterName, const std::wstring& privateAdapterDesc) {
    HRESULT hr;
    
    // Initialize COM if not already (Caller usually does, but we can check or just call CoCreate)
    // Since Main uses RoInitialize(RO_INIT_MULTITHREADED), we are in MTA.
    
    ComPtr<INetSharingManager> pNSM;
    hr = CoCreateInstance(CLSID_NetSharingManager, NULL, CLSCTX_ALL, __uuidof(INetSharingManager), &pNSM);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to create NetSharingManager. Error: " << std::hex << hr << std::endl;
        return false;
    }

    ComPtr<INetSharingEveryConnectionCollection> pEveryConnectionCollection;
    hr = pNSM->get_EnumEveryConnection(&pEveryConnectionCollection);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to get EnumEveryConnection. Error: " << std::hex << hr << std::endl;
        return false;
    }

    ComPtr<IEnumVARIANT> pEnum;
    hr = pEveryConnectionCollection->get__NewEnum(&pEnum);
    if (FAILED(hr)) return false;

    VARIANT v;
    VariantInit(&v);

    ComPtr<INetConnection> pPublicConn;
    ComPtr<INetConnection> pPrivateConn;

    while (pEnum->Next(1, &v, NULL) == S_OK) {
        if (v.vt != VT_UNKNOWN && v.vt != VT_DISPATCH) {
            VariantClear(&v);
            continue;
        }

        ComPtr<INetConnection> pConnection;
        v.punkVal->QueryInterface(__uuidof(INetConnection), &pConnection);
        VariantClear(&v);

        if (!pConnection) continue;

        NETCON_PROPERTIES* pProps = NULL;
        hr = pConnection->GetProperties(&pProps);
        if (FAILED(hr)) continue;

        std::wstring name = pProps->pszwName;
        std::wstring desc = pProps->pszwDeviceName; 

        // std::wcout << L"Scanning: " << name << L" (" << desc << L") Status:" << pProps->Status << std::endl;

        if (name == publicAdapterName) {
            pPublicConn = pConnection;
        }
        else if (desc.find(privateAdapterDesc) != std::wstring::npos) {
            if (pProps->Status == NCS_CONNECTED) {
                pPrivateConn = pConnection;
            }
        }

        CoTaskMemFree(pProps->pszwName);
        CoTaskMemFree(pProps->pszwDeviceName);
        CoTaskMemFree(pProps);
        
        if (pPublicConn && pPrivateConn) break;
    }

    if (!pPublicConn) {
        std::wcerr << L"Error: Could not find Public Adapter: " << publicAdapterName << std::endl;
        return false;
    }
    if (!pPrivateConn) {
        std::wcerr << L"Error: Could not find Private Adapter with description: " << privateAdapterDesc << std::endl;
        return false;
    }

    // Disable sharing first to reset? Or just enable.
    // If we enable public on one, we might need to be careful.
    
    // Enable Shared-Public on Public Connection
    if (!SetConnectionSharing(pNSM.Get(), pPublicConn.Get(), ICSSHARINGTYPE_PUBLIC)) {
        std::wcerr << L"Failed to enable Public Sharing on " << publicAdapterName << std::endl;
        return false;
    }

    // Enable Shared-Private on Private Connection
    if (!SetConnectionSharing(pNSM.Get(), pPrivateConn.Get(), ICSSHARINGTYPE_PRIVATE)) {
        std::wcerr << L"Failed to enable Private Sharing on WiFi adapter" << std::endl;
        return false;
    }

    std::wcout << L"ICS Enabled Successfully." << std::endl;
    return true;
}

bool IcsManager::SetConnectionSharing(INetSharingManager* pNSM, INetConnection* pConnection, int type) {
    HRESULT hr;
    
    ComPtr<INetSharingConfiguration> pConfig;
    hr = pNSM->get_INetSharingConfigurationForINetConnection(pConnection, &pConfig);
    if (FAILED(hr)) return false;

    // Check if already enabled
    // SHARING_CONNECTION_TYPE currentType;
    // VARIANT_BOOL enabled;
    // pConfig->get_SharingEnabled(&enabled);
    // pConfig->get_SharingConnectionType(&currentType);
    
    // Force enable
    hr = pConfig->EnableSharing((SHARING_CONNECTION_TYPE)type);
    if (FAILED(hr)) {
        // It might return S_FALSE if already enabled, but usually returns error if something conflicts
        // If hr == 0x80070032 (Not supported), etc.
        // std::wcerr << L"EnableSharing type " << type << L" failed: " << std::hex << hr << std::endl;
        return false;
    }
    return true;
}