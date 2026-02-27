#pragma once

#include <windows.h>
#include <wrl/client.h>
#include <wrl/wrappers/corewrappers.h>
#include <wrl/event.h>
#include <windows.foundation.h>
#include <windows.devices.wifidirect.h>
#include <windows.security.credentials.h>
#include <windows.networking.h>
#include <windows.devices.enumeration.h>

#include <string>
#include <map>
#include <exception>
#include <sstream>

#pragma comment(lib, "runtimeobject.lib")

// Exception class
class WiFiAPException : public std::exception
{
public:
    WiFiAPException(const char* message)
        : std::exception(message), _hr(S_OK) {}

    WiFiAPException(const char* message, HRESULT hr)
        : std::exception(message), _hr(hr) {}

    HRESULT GetErrorCode() const { return _hr; }
private:
    HRESULT _hr;
};

// Listener interface
class IWiFiAPListener
{
public:
    virtual ~IWiFiAPListener() {}
    virtual void OnDeviceConnected(std::wstring remoteHostName) = 0;
    virtual void OnDeviceDisconnected(std::wstring deviceId) = 0;
    virtual void OnAdvertisementStarted() = 0;
    virtual void OnAdvertisementStopped(std::wstring message) = 0;
    virtual void OnAdvertisementAborted(std::wstring message) = 0;
    virtual void OnAsyncException(std::wstring message) = 0;
    virtual void LogMessage(std::wstring message) = 0;
};

// Helper class for Wi-Fi Direct Legacy AP
class WiFiAPManager
{
public:
    static WiFiAPManager& instance();

    void SetSSID(const std::wstring& ssid);
    std::wstring GetSSID() const { return _ssid; }

    void SetPassphrase(const std::wstring& passphrase);
    std::wstring GetPassphrase() const { return _passphrase; }


    void SetIP(const std::string& targetIp);

    void RegisterListener(IWiFiAPListener* listener) { _listener = listener; }

    void Start();
    void CheckKeepAlive();

private:
    WiFiAPManager();
    ~WiFiAPManager();
    void StartListener();
    void Reset();

    Microsoft::WRL::ComPtr<ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher> _publisher;
    Microsoft::WRL::ComPtr<ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement> _advertisement;
    Microsoft::WRL::ComPtr<ABI::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings> _legacySettings;
    Microsoft::WRL::ComPtr<ABI::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener> _connectionListener;

    std::map<std::wstring, Microsoft::WRL::ComPtr<ABI::Windows::Devices::WiFiDirect::IWiFiDirectDevice>> _connectedDevices;
    std::map<std::wstring, EventRegistrationToken> _connectedDeviceStatusChangedTokens;

    EventRegistrationToken _connectionRequestedToken;
    EventRegistrationToken _statusChangedToken;

    bool _ssidProvided;
    std::wstring _ssid;
    bool _passphraseProvided;
    std::wstring _passphrase;

    IWiFiAPListener* _listener;
};
