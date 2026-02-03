#include "ics_manager.h"
#include <iostream>
#include <vector>

using namespace Microsoft::WRL;

// =============================================================
// 手动定义缺失的 COM 接口和结构体 (Self-contained definitions)
// =============================================================

// 1. 枚举定义
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

// 2. 结构体定义
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

// 前置声明
struct INetSharingPortMappingCollection;
struct INetSharingPortMapping;
struct INetConnectionProps;

// 3. 接口定义

// INetConnection
MIDL_INTERFACE("C08956A1-1CD3-11D1-B1C5-00805FC1270E")
INetConnection : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE Connect(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE Disconnect(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE Delete(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE Duplicate(
        /* [in] */ LPCWSTR pszwDuplicateName,
        /* [out] */ INetConnection **ppCon) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetProperties(
        /* [out] */ NETCON_PROPERTIES **ppProps) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetUiObjectClassId(
        /* [out] */ CLSID *pclsid) = 0;
    virtual HRESULT STDMETHODCALLTYPE Rename(
        /* [in] */ LPCWSTR pszwNewName) = 0;
};

// INetSharingConfiguration
MIDL_INTERFACE("F4217D55-1CD3-11D1-B1C5-00805FC1270E")
INetSharingConfiguration : public IDispatch
{
public:
    virtual HRESULT STDMETHODCALLTYPE get_EnumPortMappings(
        /* [in] */ SHARING_CONNECTION_TYPE Flags,
        /* [retval][out] */ INetSharingPortMappingCollection **ppColl) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE AddPortMapping(
        /* [in] */ BSTR bstrName,
        /* [in] */ unsigned char ucIPProtocol,
        /* [in] */ unsigned short usExternalPort,
        /* [in] */ unsigned short usInternalPort,
        /* [in] */ DWORD dwOptions,
        /* [in] */ BSTR bstrTargetNameOrIPAddress,
        /* [in] */ BSTR bstrTargetPortName,
        /* [retval][out] */ INetSharingPortMapping **ppMapping) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE RemovePortMapping(
        /* [in] */ INetSharingPortMapping *pMapping) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_SharingEnabled(
        /* [retval][out] */ VARIANT_BOOL *pbEnabled) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_SharingConnectionType(
        /* [retval][out] */ SHARING_CONNECTION_TYPE *pType) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE DisableSharing( void) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE EnableSharing(
        /* [in] */ SHARING_CONNECTION_TYPE Type) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_InternetFirewallEnabled(
        /* [retval][out] */ VARIANT_BOOL *pbEnabled) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE DisableInternetFirewall( void) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE EnableInternetFirewall( void) = 0;
};

// INetSharingEveryConnectionCollection
MIDL_INTERFACE("33C56D62-1CD3-11D1-B1C5-00805FC1270E")
INetSharingEveryConnectionCollection : public IDispatch
{
public:
    virtual HRESULT STDMETHODCALLTYPE get__NewEnum(
        /* [retval][out] */ IUnknown **pVal) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_Count(
        /* [retval][out] */ long *pVal) = 0;
};

// INetSharingManager
MIDL_INTERFACE("C08956B7-1CD3-11D1-B1C5-00805FC1270E")
INetSharingManager : public IDispatch
{
public:
    virtual HRESULT STDMETHODCALLTYPE get_SharingInstalled(
        /* [retval][out] */ VARIANT_BOOL *pbInstalled) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_EnumPublicConnections(
        /* [in] */ SHARING_CONNECTION_TYPE Flags,
        /* [retval][out] */ IUnknown **ppColl) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_EnumPrivateConnections(
        /* [in] */ SHARING_CONNECTION_TYPE Flags,
        /* [retval][out] */ IUnknown **ppColl) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_INetSharingConfigurationForINetConnection(
        /* [in] */ INetConnection *pNetConnection,
        /* [retval][out] */ INetSharingConfiguration **ppNetSharingConfiguration) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_EnumEveryConnection(
        /* [retval][out] */ INetSharingEveryConnectionCollection **ppColl) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_NetConnectionProps(
        /* [in] */ INetConnection *pNetConnection,
        /* [retval][out] */ INetConnectionProps **ppProps) = 0;
};

// =============================================================
// 实现部分
// =============================================================

// Check if CLSID_NetSharingManager is defined
const CLSID CLSID_NetSharingManager = { 0x5C63C1AD, 0x3956, 0x4FF8, { 0x84, 0x86, 0x40, 0x03, 0x47, 0x58, 0x31, 0x5B } };

bool IcsManager::EnableICS(const std::wstring& publicAdapterName, const std::wstring& privateAdapterDesc) {
    HRESULT hr;
    
    // Initialize COM if not already
    
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
    ComPtr<IUnknown> pUnkEnum;
    hr = pEveryConnectionCollection->get__NewEnum(&pUnkEnum);
    if (FAILED(hr)) return false;
    
    hr = pUnkEnum.As(&pEnum);
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

    // Enable Shared-Public on Public Connection
    // Pass '0' for ICSSHARINGTYPE_PUBLIC
    if (!SetConnectionSharing(pNSM.Get(), pPublicConn.Get(), 0)) {
        std::wcerr << L"Failed to enable Public Sharing on " << publicAdapterName << std::endl;
        return false;
    }

    // Enable Shared-Private on Private Connection
    // Pass '1' for ICSSHARINGTYPE_PRIVATE
    if (!SetConnectionSharing(pNSM.Get(), pPrivateConn.Get(), 1)) {
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

    // Force enable sharing with the specified type
    hr = pConfig->EnableSharing((SHARING_CONNECTION_TYPE)type);
    if (FAILED(hr)) {
        // std::wcerr << L"EnableSharing failed: " << std::hex << hr << std::endl;
        return false;
    }
    return true;
}
