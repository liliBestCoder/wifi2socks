#include "wifi_ap.h"
#include <iostream>
#include <sstream>

using namespace ABI::Windows::Foundation;
using namespace ABI::Windows::Foundation::Collections;
using namespace ABI::Windows::Devices::Enumeration;
using namespace ABI::Windows::Devices::WiFiDirect;
using namespace ABI::Windows::Security::Credentials;
using namespace ABI::Windows::Networking;
using namespace Microsoft::WRL;
using namespace Microsoft::WRL::Wrappers;

typedef __FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectConnectionListener_Windows__CDevices__CWiFiDirect__CWiFiDirectConnectionRequestedEventArgs ConnectionRequestedHandler;
typedef __FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisher_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisherStatusChangedEventArgs StatusChangedHandler;
typedef __FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice_IInspectable ConnectionStatusChangedHandler;
typedef __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice FromIdAsyncHandler;
typedef __FIVectorView_1_Windows__CNetworking__CEndpointPair EndpointPairCollection;

WiFiAPManager& WiFiAPManager::instance()
{
    static WiFiAPManager inst;
    return inst;
}

WiFiAPManager::WiFiAPManager()
    : _ssidProvided(false),
      _passphraseProvided(false),
      _listener(nullptr)
{
}

WiFiAPManager::~WiFiAPManager()
{
    if (_publisher.Get() != nullptr)
    {
        _publisher->Stop();
    }
    Reset();
}

void WiFiAPManager::SetSSID(const std::wstring& ssid)
{
    _ssid = ssid;
    _ssidProvided = true;
}

void WiFiAPManager::SetPassphrase(const std::wstring& passphrase)
{
    _passphrase = passphrase;
    _passphraseProvided = true;
}

void WiFiAPManager::Start()
{
    HRESULT hr = S_OK;

    Reset();

    hr = Windows::Foundation::ActivateInstance(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectAdvertisementPublisher).Get(), &_publisher);
    if (FAILED(hr))
    {
        throw WiFiAPException("ActivateInstance for WiFiDirectAdvertisementPublisher failed", hr);
    }

    hr = _publisher->add_StatusChanged(
        Callback<StatusChangedHandler>([this](IWiFiDirectAdvertisementPublisher* sender, IWiFiDirectAdvertisementPublisherStatusChangedEventArgs* args) -> HRESULT
    {
        HRESULT hr = S_OK;
        WiFiDirectAdvertisementPublisherStatus status;
        WiFiDirectError error;

        try
        {
            hr = args->get_Status(&status);
            if (FAILED(hr)) throw WiFiAPException("Get Status failed", hr);

            switch (status)
            {
                case WiFiDirectAdvertisementPublisherStatus_Started:
                {
                    StartListener();
                    if (_listener) _listener->OnAdvertisementStarted();
                    break;
                }
                case WiFiDirectAdvertisementPublisherStatus_Aborted:
                {
                    hr = args->get_Error(&error);
                    if (FAILED(hr)) throw WiFiAPException("Get Error failed", hr);

                    std::wstring message;
                    switch (error)
                    {
                    case WiFiDirectError_RadioNotAvailable: message = L"Advertisement aborted, Wi-Fi radio is turned off"; break;
                    case WiFiDirectError_ResourceInUse: message = L"Advertisement aborted, Resource In Use"; break;
                    default: message = L"Advertisement aborted, unknown reason"; break;
                    }

                    if (_listener) _listener->OnAdvertisementAborted(message);

                    // Auto-Restart logic for Aborted state
                    // Use a small delay to avoid tight loop in case of persistent hardware error
                    std::thread([this]() {
                        Sleep(2000);
                        try { this->Start(); } catch(...) {}
                    }).detach();
                    break;
                }
                case WiFiDirectAdvertisementPublisherStatus_Stopped:
                {
                    if (_listener) _listener->OnAdvertisementStopped(L"Advertisement stopped");
                    break;
                }
            }
        }
        catch (WiFiAPException& e)
        {
            if (_listener)
            {
                std::wostringstream ss;
                ss << e.what() << ": " << e.GetErrorCode();
                _listener->OnAsyncException(ss.str());
            }
            return e.GetErrorCode();
        }
        return hr;
    }).Get(), &_statusChangedToken);

    hr = _publisher->get_Advertisement(_advertisement.GetAddressOf());
    if (FAILED(hr)) throw WiFiAPException("Get advertisement failed", hr);

    hr = _advertisement->put_IsAutonomousGroupOwnerEnabled(true);
    if (FAILED(hr)) throw WiFiAPException("Set is autonomous group owner failed", hr);

    hr = _advertisement->get_LegacySettings(_legacySettings.GetAddressOf());
    if (FAILED(hr)) throw WiFiAPException("Get legacy settings failed", hr);

    hr = _legacySettings->put_IsEnabled(true);
    if (FAILED(hr)) throw WiFiAPException("Set is enabled failed", hr);

    HString hstrSSID;
    if (_ssidProvided)
    {
        hr = hstrSSID.Set(_ssid.c_str());
        if (FAILED(hr)) throw WiFiAPException("Failed to create HSTRING for SSID", hr);

        hr = _legacySettings->put_Ssid(hstrSSID.Get());
        if (FAILED(hr)) throw WiFiAPException("Set SSID failed", hr);
    }
    else
    {
        hr = _legacySettings->get_Ssid(hstrSSID.GetAddressOf());
        if (FAILED(hr)) throw WiFiAPException("Get SSID failed", hr);
        _ssid = hstrSSID.GetRawBuffer(nullptr);
    }

    ComPtr<IPasswordCredential> passwordCredential;
    hr = _legacySettings->get_Passphrase(passwordCredential.GetAddressOf());
    if (FAILED(hr)) throw WiFiAPException("Get Passphrase credential failed", hr);

    HString hstrPassphrase;
    if (_passphraseProvided)
    {
        hr = hstrPassphrase.Set(_passphrase.c_str());
        if (FAILED(hr)) throw WiFiAPException("Failed to create HSTRING for Passphrase", hr);

        hr = passwordCredential->put_Password(hstrPassphrase.Get());
        if (FAILED(hr)) throw WiFiAPException("Set Passphrase failed", hr);
    }
    else
    {
        hr = passwordCredential->get_Password(hstrPassphrase.GetAddressOf());
        if (FAILED(hr)) throw WiFiAPException("Get Passphrase failed", hr);
        _passphrase = hstrPassphrase.GetRawBuffer(nullptr);
    }

    hr = _publisher->Start();
    if (FAILED(hr)) throw WiFiAPException("Start failed", hr);
}

void WiFiAPManager::Stop()
{
    HRESULT hr = S_OK;
    if (_publisher.Get() != nullptr)
    {
        hr = _publisher->Stop();
        if (FAILED(hr)) throw WiFiAPException("Stop failed", hr);
    }
}

void WiFiAPManager::CheckKeepAlive()
{
    // Periodically probe connected devices to prevent Windows from reclaiming the COM objects
    // or dropping the connection due to perceived inactivity.
    std::vector<std::wstring> to_remove;
    for (auto& pair : _connectedDevices)
    {
        ComPtr<EndpointPairCollection> endpointPairs;
        HRESULT hr = pair.second->GetConnectionEndpointPairs(endpointPairs.GetAddressOf());
        if (FAILED(hr))
        {
            // If probing fails with a serious error, the device might be gone
            if (hr == HRESULT_FROM_WIN32(ERROR_DEVICE_NOT_CONNECTED) || hr == RPC_E_DISCONNECTED)
            {
                to_remove.push_back(pair.first);
            }
        }
    }

    for (const auto& id : to_remove)
    {
        auto itDevice = _connectedDevices.find(id);
        auto itToken = _connectedDeviceStatusChangedTokens.find(id);
        if (itToken != _connectedDeviceStatusChangedTokens.end())
        {
            if (itDevice != _connectedDevices.end())
                itDevice->second->remove_ConnectionStatusChanged(itToken->second);
            _connectedDeviceStatusChangedTokens.erase(itToken);
        }
        if (itDevice != _connectedDevices.end())
            _connectedDevices.erase(itDevice);
        
        if (_listener) _listener->OnDeviceDisconnected(id);
    }
}

void WiFiAPManager::StartListener()
{
    HRESULT hr = S_OK;

    hr = Windows::Foundation::ActivateInstance(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectConnectionListener).Get(), &_connectionListener);
    if (FAILED(hr)) throw WiFiAPException("ActivateInstance for WiFiDirectConnectionListener failed", hr);

    hr = _connectionListener->add_ConnectionRequested(
        Callback<ConnectionRequestedHandler>([this](IWiFiDirectConnectionListener* sender, IWiFiDirectConnectionRequestedEventArgs* args) -> HRESULT
    {
        HRESULT hr = S_OK;
        ComPtr<IWiFiDirectConnectionRequest> request;
        ComPtr<IDeviceInformation> deviceInformation;
        HString deviceId;
        ComPtr<IWiFiDirectDeviceStatics> wfdStatics;

        if (_listener) _listener->LogMessage(L"Connection Requested...");

        try
        {
            hr = args->GetConnectionRequest(request.GetAddressOf());
            if (FAILED(hr)) throw WiFiAPException("GetConnectionRequest failed", hr);

            hr = request->get_DeviceInformation(deviceInformation.GetAddressOf());
            if (FAILED(hr)) throw WiFiAPException("Get device information failed", hr);

            hr = GetActivationFactory(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectDevice).Get(), &wfdStatics);
            if (FAILED(hr)) throw WiFiAPException("GetActivationFactory failed", hr);

            hr = deviceInformation->get_Id(deviceId.GetAddressOf());
            if (FAILED(hr)) throw WiFiAPException("Get ID failed", hr);

            ComPtr<IAsyncOperation<WiFiDirectDevice*>> asyncAction;
            hr = wfdStatics->FromIdAsync(deviceId.Get(), &asyncAction);
            if (FAILED(hr)) throw WiFiAPException("FromIdAsync failed", hr);

            hr = asyncAction->put_Completed(Callback<FromIdAsyncHandler>([this](IAsyncOperation<WiFiDirectDevice*>* pHandler, AsyncStatus status) -> HRESULT
            {
                HRESULT hr = S_OK;
                ComPtr<IWiFiDirectDevice> wfdDevice;
                ComPtr<EndpointPairCollection> endpointPairs;
                ComPtr<IEndpointPair> endpointPair;
                ComPtr<IHostName> remoteHostName;
                HString remoteHostNameDisplay;
                HString deviceId;

                try
                {
                    if (status == AsyncStatus::Completed)
                    {
                        hr = pHandler->GetResults(wfdDevice.GetAddressOf());
                        if (FAILED(hr)) throw WiFiAPException("GetResults failed", hr);

                        hr = wfdDevice->GetConnectionEndpointPairs(endpointPairs.GetAddressOf());
                        if (FAILED(hr)) throw WiFiAPException("GetConnectionEndpointPairs failed", hr);

                        // Sometimes endpoint pairs might be empty, check size? 
                        // The original code assumed index 0 exists. We will keep it but it might be risky.
                        // Ideally checking size would be better.
                        
                        unsigned int size = 0;
                        endpointPairs->get_Size(&size);
                        if(size > 0) {
                             hr = endpointPairs->GetAt(0, endpointPair.GetAddressOf());
                             if (FAILED(hr)) throw WiFiAPException("GetAt(0) failed", hr);
                             
                             hr = endpointPair->get_RemoteHostName(remoteHostName.GetAddressOf());
                             if (FAILED(hr)) throw WiFiAPException("get_RemoteHostName failed", hr);

                             hr = remoteHostName->get_DisplayName(remoteHostNameDisplay.GetAddressOf());
                             if (FAILED(hr)) throw WiFiAPException("get_DisplayName failed", hr);
                        } else {
                             // Fallback or just ignore name
                        }

                        EventRegistrationToken statusChangedToken;
                        hr = wfdDevice->add_ConnectionStatusChanged(Callback<ConnectionStatusChangedHandler>([this](IWiFiDirectDevice* sender, IInspectable*) -> HRESULT
                        {
                            WiFiDirectConnectionStatus status;
                            HString deviceId;
                            HRESULT hr = S_OK;

                            try
                            {
                                hr = sender->get_ConnectionStatus(&status);
                                if (FAILED(hr)) throw WiFiAPException("get_ConnectionStatus failed", hr);

                                if (status == WiFiDirectConnectionStatus_Disconnected)
                                {
                                    hr = sender->get_DeviceId(deviceId.GetAddressOf());
                                    if (FAILED(hr)) throw WiFiAPException("get_DeviceId failed", hr);

                                    auto itDevice = _connectedDevices.find(deviceId.GetRawBuffer(nullptr));
                                    auto itToken = _connectedDeviceStatusChangedTokens.find(deviceId.GetRawBuffer(nullptr));

                                    if (itToken != _connectedDeviceStatusChangedTokens.end())
                                    {
                                        if (itDevice != _connectedDevices.end())
                                            itDevice->second->remove_ConnectionStatusChanged(itToken->second);
                                        _connectedDeviceStatusChangedTokens.erase(itToken);
                                    }

                                    if (itDevice != _connectedDevices.end())
                                        _connectedDevices.erase(itDevice);

                                    if (_listener) _listener->OnDeviceDisconnected(deviceId.GetRawBuffer(nullptr));
                                }
                            }
                            catch (WiFiAPException& e)
                            {
                                if (_listener)
                                {
                                    std::wostringstream ss;
                                    ss << e.what() << ": " << e.GetErrorCode();
                                    _listener->OnAsyncException(ss.str());
                                }
                                return e.GetErrorCode();
                            }
                            return hr;
                        }).Get(), &statusChangedToken);

                        hr = wfdDevice->get_DeviceId(deviceId.GetAddressOf());
                        if (FAILED(hr)) throw WiFiAPException("get_DeviceId failed", hr);

                        _connectedDevices.insert(std::make_pair(deviceId.GetRawBuffer(nullptr), wfdDevice));
                        _connectedDeviceStatusChangedTokens.insert(std::make_pair(deviceId.GetRawBuffer(nullptr), statusChangedToken));

                        if (_listener)
                        {
                            _listener->OnDeviceConnected(remoteHostNameDisplay.GetRawBuffer(nullptr) ? remoteHostNameDisplay.GetRawBuffer(nullptr) : L"Unknown");
                        }
                    }
                    else
                    {
                        if (_listener)
                        {
                             std::wstring msg = L"Device connection status: ";
                             if (status == AsyncStatus::Started) msg += L"Started";
                             else if (status == AsyncStatus::Canceled) msg += L"Canceled";
                             else if (status == AsyncStatus::Error) msg += L"Error";
                             _listener->LogMessage(msg);
                        }
                    }
                }
                catch (WiFiAPException& e)
                {
                    if (_listener)
                    {
                        std::wostringstream ss;
                        ss << e.what() << ": " << e.GetErrorCode();
                        _listener->OnAsyncException(ss.str());
                    }
                    return e.GetErrorCode();
                }
                return hr;
            }).Get());
            if (FAILED(hr)) throw WiFiAPException("put_Completed failed", hr);

        }
        catch (WiFiAPException& e)
        {
            if (_listener)
            {
                std::wostringstream ss;
                ss << e.what() << ": " << e.GetErrorCode();
                _listener->OnAsyncException(ss.str());
            }
            return e.GetErrorCode();
        }
        return hr;
    }).Get(), &_connectionRequestedToken);
    
    if (FAILED(hr)) throw WiFiAPException("add_ConnectionRequested failed", hr);
    
    if (_listener) _listener->LogMessage(L"Connection Listener is ready");
}

void WiFiAPManager::Reset()
{
    if (_connectionListener.Get() != nullptr)
    {
        _connectionListener->remove_ConnectionRequested(_connectionRequestedToken);
    }

    if (_publisher.Get() != nullptr)
    {
        _publisher->remove_StatusChanged(_statusChangedToken);
    }

    // Explicitly unregister handlers from connected devices before clearing
    for (auto& pair : _connectedDevices)
    {
        auto itToken = _connectedDeviceStatusChangedTokens.find(pair.first);
        if (itToken != _connectedDeviceStatusChangedTokens.end())
        {
            pair.second->remove_ConnectionStatusChanged(itToken->second);
        }
    }

    _legacySettings.Reset();
    _advertisement.Reset();
    _publisher.Reset();
    _connectionListener.Reset();

    _connectedDevices.clear();
    _connectedDeviceStatusChangedTokens.clear();
}
