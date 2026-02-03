#include "ics_manager.h"
#include <iostream>
#include <vector>

using namespace Microsoft::WRL;

// --- Manual Definitions for Missing HNetCfg.h ---

typedef enum tagSHARING_CONNECTION_TYPE {
    ICSSHARINGTYPE_PUBLIC = 0,
    ICSSHARINGTYPE_PRIVATE = 1
} SHARING_CONNECTION_TYPE;

// Forward declarations
struct INetSharingPortMappingCollection;
struct INetSharingPortMapping;

// Interfaces
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

MIDL_INTERFACE("33C56D62-1CD3-11D1-B1C5-00805FC1270E")
INetSharingEveryConnectionCollection : public IDispatch
{
public:
    virtual HRESULT STDMETHODCALLTYPE get__NewEnum(
        /* [retval][out] */ IUnknown **pVal) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_Count(
        /* [retval][out] */ long *pVal) = 0;
};

MIDL_INTERFACE("C08956B7-1CD3-11D1-B1C5-00805FC1270E")
INetSharingManager : public IDispatch
{
public:
    virtual HRESULT STDMETHODCALLTYPE get_SharingInstalled(
        /* [retval][out] */ VARIANT_BOOL *pbInstalled) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_EnumPublicConnections(
        /* [in] */ SHARING_CONNECTION_TYPE Flags,
        /* [retval][out] */ /*INetSharingPublicConnectionCollection*/ IUnknown **ppColl) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_EnumPrivateConnections(
        /* [in] */ SHARING_CONNECTION_TYPE Flags,
        /* [retval][out] */ /*INetSharingPrivateConnectionCollection*/ IUnknown **ppColl) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_INetSharingConfigurationForINetConnection(
        /* [in] */ INetConnection *pNetConnection,
        /* [retval][out] */ INetSharingConfiguration **ppNetSharingConfiguration) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_EnumEveryConnection(
        /* [retval][out] */ INetSharingEveryConnectionCollection **ppColl) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE get_NetConnectionProps(
        /* [in] */ INetConnection *pNetConnection,
        /* [retval][out] */ INetConnectionProps **ppProps) = 0;
};

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
    // Note: get__NewEnum returns IUnknown, we need to QI for IEnumVARIANT
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

    // Force enable
    hr = pConfig->EnableSharing((SHARING_CONNECTION_TYPE)type);
    if (FAILED(hr)) {
        // std::wcerr << L"EnableSharing type " << type << L" failed: " << std::hex << hr << std::endl;
        return false;
    }
    return true;
}