#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "wifi_ap.h"
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>
#include <string>
#include <chrono>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// 辅助函数：修改IP
bool ForceSetStaticIP(const std::string& targetIp);
// 辅助函数：停止ICS服务
void StopICSService();

using namespace ABI::Windows::Foundation;
using namespace ABI::Windows::Foundation::Collections;
using namespace ABI::Windows::Devices::Enumeration;
using namespace ABI::Windows::Devices::WiFiDirect;
using namespace ABI::Windows::Security::Credentials;
using namespace ABI::Windows::Networking;
using namespace Microsoft::WRL;
using namespace Microsoft::WRL::Wrappers;

// 类型定义
typedef __FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectConnectionListener_Windows__CDevices__CWiFiDirect__CWiFiDirectConnectionRequestedEventArgs ConnectionRequestedHandler;
typedef __FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisher_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisherStatusChangedEventArgs StatusChangedHandler;
typedef __FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice_IInspectable ConnectionStatusChangedHandler;
typedef __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice FromIdAsyncHandler;
typedef __FIVectorView_1_Windows__CNetworking__CEndpointPair EndpointPairCollection;

WiFiAPManager& WiFiAPManager::instance() {
    static WiFiAPManager inst;
    return inst;
}

WiFiAPManager::WiFiAPManager() : _ssidProvided(false), _passphraseProvided(false), _listener(nullptr) {}

WiFiAPManager::~WiFiAPManager() {
    if (_publisher.Get() != nullptr) _publisher->Stop();
    Reset();
}

void WiFiAPManager::SetSSID(const std::wstring& ssid) { _ssid = ssid; _ssidProvided = true; }
void WiFiAPManager::SetPassphrase(const std::wstring& passphrase) { _passphrase = passphrase; _passphraseProvided = true; }

// --- 补全 CheckKeepAlive 实现，解决链接错误 ---
void WiFiAPManager::CheckKeepAlive() {
    std::vector<std::wstring> to_remove;
    for (auto& pair : _connectedDevices) {
        ComPtr<EndpointPairCollection> endpointPairs;
        HRESULT hr = pair.second->GetConnectionEndpointPairs(endpointPairs.GetAddressOf());
        if (FAILED(hr)) {
            if (hr == HRESULT_FROM_WIN32(ERROR_DEVICE_NOT_CONNECTED) || hr == RPC_E_DISCONNECTED) {
                to_remove.push_back(pair.first);
            }
        }
    }
    for (const auto& id : to_remove) {
        auto it = _connectedDevices.find(id);
        if (it != _connectedDevices.end()) {
            _connectedDevices.erase(it);
            if (_listener) _listener->OnDeviceDisconnected(id);
        }
    }
}

void WiFiAPManager::Start() {
    // 启动前先尝试停止 ICS 服务，防止其锁定 IP 137.1
    StopICSService();

    HRESULT hr = S_OK;
    Reset();

    hr = Windows::Foundation::ActivateInstance(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectAdvertisementPublisher).Get(), &_publisher);
    if (FAILED(hr)) throw WiFiAPException("ActivateInstance failed", hr);

    hr = _publisher->add_StatusChanged(Callback<StatusChangedHandler>([this](IWiFiDirectAdvertisementPublisher* sender, IWiFiDirectAdvertisementPublisherStatusChangedEventArgs* args) -> HRESULT {
        WiFiDirectAdvertisementPublisherStatus status;
        args->get_Status(&status);
        if (status == WiFiDirectAdvertisementPublisherStatus_Started) {
            StartListener();
            if (_listener) _listener->OnAdvertisementStarted();
        }
        return S_OK;
        }).Get(), &_statusChangedToken);

    hr = _publisher->get_Advertisement(_advertisement.GetAddressOf());
    _advertisement->put_IsAutonomousGroupOwnerEnabled(true);
    _advertisement->get_LegacySettings(_legacySettings.GetAddressOf());
    _legacySettings->put_IsEnabled(true);

    if (_ssidProvided) {
        HString hstrSSID;
        hstrSSID.Set(_ssid.c_str());
        _legacySettings->put_Ssid(hstrSSID.Get());
    }

    ComPtr<IPasswordCredential> passwordCredential;
    _legacySettings->get_Passphrase(passwordCredential.GetAddressOf());
    if (_passphraseProvided) {
        HString hstrPass;
        hstrPass.Set(_passphrase.c_str());
        passwordCredential->put_Password(hstrPass.Get());
    }

    hr = _publisher->Start();
    if (FAILED(hr)) throw WiFiAPException("Start failed", hr);
}

void WiFiAPManager::StartListener() {
    Windows::Foundation::ActivateInstance(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectConnectionListener).Get(), &_connectionListener);
    _connectionListener->add_ConnectionRequested(Callback<ConnectionRequestedHandler>([this](IWiFiDirectConnectionListener* sender, IWiFiDirectConnectionRequestedEventArgs* args) -> HRESULT {
        ComPtr<IWiFiDirectConnectionRequest> request;
        ComPtr<IDeviceInformation> deviceInfo;
        HString deviceId;
        ComPtr<IWiFiDirectDeviceStatics> wfdStatics;

        args->GetConnectionRequest(request.GetAddressOf());
        request->get_DeviceInformation(deviceInfo.GetAddressOf());
        GetActivationFactory(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectDevice).Get(), &wfdStatics);
        deviceInfo->get_Id(deviceId.GetAddressOf());

        ComPtr<IAsyncOperation<WiFiDirectDevice*>> asyncAction;
        wfdStatics->FromIdAsync(deviceId.Get(), &asyncAction);
        asyncAction->put_Completed(Callback<FromIdAsyncHandler>([this](IAsyncOperation<WiFiDirectDevice*>* pHandler, AsyncStatus status) -> HRESULT {
            if (status == AsyncStatus::Completed) {
                ComPtr<IWiFiDirectDevice> wfdDevice;
                pHandler->GetResults(wfdDevice.GetAddressOf());
                HString dId;
                wfdDevice->get_DeviceId(dId.GetAddressOf());
                _connectedDevices[dId.GetRawBuffer(nullptr)] = wfdDevice;

                if (_listener) _listener->OnDeviceConnected(L"Connected Device");

                // 异步设置 IP，增加重试机制
                std::thread([]() {
                    for (int i = 0; i < 3; ++i) { // 尝试3次
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        if (ForceSetStaticIP("192.168.11.1")) break;
                    }
                    }).detach();
            }
            return S_OK;
            }).Get());
        return S_OK;
        }).Get(), &_connectionRequestedToken);
}

void WiFiAPManager::Reset() {
    if (_connectionListener) _connectionListener->remove_ConnectionRequested(_connectionRequestedToken);
    if (_publisher) _publisher->remove_StatusChanged(_statusChangedToken);
    _connectedDevices.clear();
    _publisher.Reset();
    _connectionListener.Reset();
}

// 核心：强制设置静态IP
bool ForceSetStaticIP(const std::string& targetIp) {
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferSize);
    std::vector<BYTE> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES* pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &bufferSize) != NO_ERROR)
        return false;

    for (auto pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
        std::wstring desc = pCurr->Description;
        // 修正：模糊匹配，适配不同编号的 Virtual Adapter
        if (desc.find(L"Wi-Fi Direct Virtual Adapter") != std::wstring::npos) {

            // 删除旧的 IPv4 地址（包括 137.1）
            for (auto pUnicast = pCurr->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    MIB_UNICASTIPADDRESS_ROW row;
                    InitializeUnicastIpAddressEntry(&row);
                    row.InterfaceLuid = pCurr->Luid;
                    row.Address.Ipv4.sin_family = AF_INET;
                    row.Address.Ipv4.sin_addr = ((sockaddr_in*)pUnicast->Address.lpSockaddr)->sin_addr;
                    DeleteUnicastIpAddressEntry(&row);
                }
            }

            // 插入 11.1
            MIB_UNICASTIPADDRESS_ROW newRow;
            InitializeUnicastIpAddressEntry(&newRow);
            newRow.InterfaceLuid = pCurr->Luid;
            newRow.Address.Ipv4.sin_family = AF_INET;
            newRow.OnLinkPrefixLength = 24;
            newRow.DadState = IpDadStatePreferred;
            inet_pton(AF_INET, targetIp.c_str(), &newRow.Address.Ipv4.sin_addr);

            return (CreateUnicastIpAddressEntry(&newRow) == NO_ERROR);
        }
    }
    return false;
}

// 停止 ICS 服务以解除对虚拟网卡的锁定
void StopICSService() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        SC_HANDLE svc = OpenService(scm, L"SharedAccess", SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS status;
            ControlService(svc, SERVICE_CONTROL_STOP, &status);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
}