#include "ics_manager.h"
#include <iostream>
#include <vector>

using namespace Microsoft::WRL;

// =============================================================
// 手动定义缺失的 COM 接口和结构体 (Self-contained definitions)
// =============================================================

typedef enum tagSHARING_CONNECTION_TYPE {
    ICSSHARINGTYPE_PUBLIC = 0,
    ICSSHARINGTYPE_PRIVATE = 1
} SHARING_CONNECTION_TYPE;

typedef enum tagNETCON_STATUS {
    NCS_DISCONNECTED = 0,
    NCS_CONNECTING = 1,
    NCS_CONNECTED = 2,
    NCS_DISCONNECTING = 3,
    NCS_HARDWARE_NOT_PRESENT = 4,
    NCS_HARDWARE_DISABLED = 5,
    NCS_HARDWARE_MALFUNCTION = 6,
    NCS_MEDIA_DISCONNECTED = 7,
    NCS_AUTHENTICATING = 8,
    NCS_AUTHENTICATION_SUCCEEDED = 9,
    NCS_AUTHENTICATION_FAILED = 10,
    NCS_INVALID_ADDRESS = 11,
    NCS_CREDENTIALS_REQUIRED = 12,
    NCS_ACTION_REQUIRED = 13,
    NCS_ACTION_REQUIRED_RETRY = 14,
    NCS_CONNECT_FAILED = 15
} NETCON_STATUS;

typedef enum tagNETCON_MEDIATYPE {
    NCM_NONE = 0,
    NCM_DIRECT = 1,
    NCM_ISDN = 2,
    NCM_LAN = 3,
    NCM_PHONE = 4,
    NCM_TUNNEL = 5,
    NCM_PPPOE = 6,
    NCM_BRIDGE = 7,
    NCM_SHAREDACCESSHOST_LAN = 8,
    NCM_SHAREDACCESSHOST_RAS = 9
} NETCON_MEDIATYPE;

typedef struct tagNETCON_PROPERTIES {
    GUID guidId;
    LPWSTR pszwName;
    LPWSTR pszwDeviceName;
    NETCON_STATUS Status;
    NETCON_MEDIATYPE MediaType;
    DWORD dwCharacter;
    CLSID clsidThisObject;
    CLSID clsidUiObject;
} NETCON_PROPERTIES;

struct INetSharingPortMappingCollection;
struct INetSharingPortMapping;
struct INetConnectionProps;

MIDL_INTERFACE("C08956A1-1CD3-11D1-B1C5-00805FC1270E")
INetConnection : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE Connect(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE Disconnect(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE Delete(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE Duplicate(LPCWSTR pszwDuplicateName, INetConnection **ppCon) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetProperties(NETCON_PROPERTIES **ppProps) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetUiObjectClassId(CLSID *pclsid) = 0;
    virtual HRESULT STDMETHODCALLTYPE Rename(LPCWSTR pszwNewName) = 0;
};

MIDL_INTERFACE("F4217D55-1CD3-11D1-B1C5-00805FC1270E")
INetSharingConfiguration : public IDispatch
{
public:
    virtual HRESULT STDMETHODCALLTYPE get_EnumPortMappings(SHARING_CONNECTION_TYPE Flags, INetSharingPortMappingCollection **ppColl) = 0;
    virtual HRESULT STDMETHODCALLTYPE AddPortMapping(BSTR bstrName, unsigned char ucIPProtocol, unsigned short usExternalPort, unsigned short usInternalPort, DWORD dwOptions, BSTR bstrTargetNameOrIPAddress, BSTR bstrTargetPortName, INetSharingPortMapping **ppMapping) = 0;
    virtual HRESULT STDMETHODCALLTYPE RemovePortMapping(INetSharingPortMapping *pMapping) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_SharingEnabled(VARIANT_BOOL *pbEnabled) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_SharingConnectionType(SHARING_CONNECTION_TYPE *pType) = 0;
    virtual HRESULT STDMETHODCALLTYPE DisableSharing(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnableSharing(SHARING_CONNECTION_TYPE Type) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_InternetFirewallEnabled(VARIANT_BOOL *pbEnabled) = 0;
    virtual HRESULT STDMETHODCALLTYPE DisableInternetFirewall(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnableInternetFirewall(void) = 0;
};

MIDL_INTERFACE("33C56D62-1CD3-11D1-B1C5-00805FC1270E")
INetSharingEveryConnectionCollection : public IDispatch
{
public:
    virtual HRESULT STDMETHODCALLTYPE get__NewEnum(IUnknown **pVal) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Count(long *pVal) = 0;
};

MIDL_INTERFACE("C08956B7-1CD3-11D1-B1C5-00805FC1270E")
INetSharingManager : public IDispatch
{
public:
    virtual HRESULT STDMETHODCALLTYPE get_SharingInstalled(VARIANT_BOOL *pbInstalled) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_EnumPublicConnections(SHARING_CONNECTION_TYPE Flags, IUnknown **ppColl) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_EnumPrivateConnections(SHARING_CONNECTION_TYPE Flags, IUnknown **ppColl) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_INetSharingConfigurationForINetConnection(INetConnection *pNetConnection, INetSharingConfiguration **ppNetSharingConfiguration) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_EnumEveryConnection(INetSharingEveryConnectionCollection **ppColl) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_NetConnectionProps(INetConnection *pNetConnection, INetConnectionProps **ppProps) = 0;
};

const CLSID CLSID_NetSharingManager = { 0x5C63C1AD, 0x3956, 0x4FF8, { 0x84, 0x86, 0x40, 0x03, 0x47, 0x58, 0x31, 0x5B } };

// --- Implementation ---

bool IcsManager::EnableICS(const std::wstring& publicAdapterName, const std::wstring& privateAdapterDesc) {
    HRESULT hr;
    
    std::wcout << L"[ICS] Starting EnableICS..." << std::endl;
    std::wcout << L"[ICS] Target Public: " << publicAdapterName << L", Private Desc: " << privateAdapterDesc << std::endl;

    ComPtr<INetSharingManager> pNSM;
    hr = CoCreateInstance(CLSID_NetSharingManager, NULL, CLSCTX_ALL, __uuidof(INetSharingManager), &pNSM);
    if (FAILED(hr)) {
        std::wcerr << L"[ICS] Failed to create NetSharingManager. Error: 0x" << std::hex << hr << std::endl;
        if (hr == REGDB_E_CLASSNOTREG) std::wcerr << L"[ICS] Error: Class not registered. Check if ICS service is enabled." << std::endl;
        return false;
    }

    ComPtr<INetSharingEveryConnectionCollection> pEveryConnectionCollection;
    hr = pNSM->get_EnumEveryConnection(&pEveryConnectionCollection);
    if (FAILED(hr)) {
        std::wcerr << L"[ICS] get_EnumEveryConnection failed. Error: 0x" << std::hex << hr << std::endl;
        return false;
    }

    ComPtr<IUnknown> pUnkEnum;
    hr = pEveryConnectionCollection->get__NewEnum(&pUnkEnum);
    if (FAILED(hr)) return false;
    
    ComPtr<IEnumVARIANT> pEnum;
    hr = pUnkEnum.As(&pEnum);
    if (FAILED(hr)) return false;

    VARIANT v;
    VariantInit(&v);

    ComPtr<INetConnection> pPublicConn;
    ComPtr<INetConnection> pPrivateConn;

    while (pEnum->Next(1, &v, NULL) == S_OK) {
        ComPtr<INetConnection> pConnection;
        if (v.vt == VT_UNKNOWN || v.vt == VT_DISPATCH) {
            v.punkVal->QueryInterface(__uuidof(INetConnection), &pConnection);
        }
        VariantClear(&v);

        if (!pConnection) continue;

        NETCON_PROPERTIES* pProps = NULL;
        hr = pConnection->GetProperties(&pProps);
        if (FAILED(hr)) continue;

        std::wstring name = pProps->pszwName;
        std::wstring device = pProps->pszwDeviceName;
        
        std::wcout << L"[ICS] Found: \"" << name << L"\" | Device: \"" << device << L"\" | Status: " << (int)pProps->Status << std::endl;

        // Match Public (TUN)
        if (name == publicAdapterName || device.find(L"Wintun") != std::wstring::npos) {
            if (!pPublicConn) {
                pPublicConn = pConnection;
                std::wcout << L"[ICS] -> Selected as Public Adapter." << std::endl;
            }
        }
        
        // Match Private (WiFi AP)
        if (device.find(privateAdapterDesc) != std::wstring::npos || 
            device.find(L"Microsoft Wi-Fi Direct Virtual") != std::wstring::npos) {
            // Note: AP might still be connecting, so we check connected OR connecting
            if (pProps->Status == NCS_CONNECTED || pProps->Status == NCS_CONNECTING) {
                pPrivateConn = pConnection;
                std::wcout << L"[ICS] -> Selected as Private Adapter." << std::endl;
            }
        }

        CoTaskMemFree(pProps->pszwName);
        CoTaskMemFree(pProps->pszwDeviceName);
        CoTaskMemFree(pProps);
    }

    if (!pPublicConn) {
        std::wcerr << L"[ICS] Error: Public Adapter not found." << std::endl;
        return false;
    }
    if (!pPrivateConn) {
        std::wcerr << L"[ICS] Error: Private Adapter (WiFi) not found. Is WiFi AP started?" << std::endl;
        return false;
    }

    // Enable Public
    if (!SetConnectionSharing(pNSM.Get(), pPublicConn.Get(), 0)) {
        std::wcerr << L"[ICS] Failed to enable Public sharing." << std::endl;
        return false;
    }

    // Enable Private
    if (!SetConnectionSharing(pNSM.Get(), pPrivateConn.Get(), 1)) {
        std::wcerr << L"[ICS] Failed to enable Private sharing." << std::endl;
        return false;
    }

    std::wcout << L"[ICS] ICS configured successfully!" << std::endl;
    return true;
}

bool IcsManager::SetConnectionSharing(INetSharingManager* pNSM, INetConnection* pConnection, int type) {
    HRESULT hr;
    ComPtr<INetSharingConfiguration> pConfig;
    hr = pNSM->get_INetSharingConfigurationForINetConnection(pConnection, &pConfig);
    if (FAILED(hr)) return false;

    // First disable if already shared elsewhere to avoid conflicts
    pConfig->DisableSharing();

    hr = pConfig->EnableSharing((SHARING_CONNECTION_TYPE)type);
    if (FAILED(hr)) {
        std::wcerr << L"[ICS] EnableSharing(" << type << L") failed. HRESULT: 0x" << std::hex << hr << std::endl;
        if (hr == 0x80070005) std::wcerr << L"[ICS] -> Access Denied. PLEASE RUN AS ADMINISTRATOR." << std::endl;
        return false;
    }
    return true;
}