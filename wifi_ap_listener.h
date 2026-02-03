#pragma once
#include "wifi_ap.h"

class Wifi2SocksWiFiListener : public IWiFiAPListener {
public:
    virtual void OnDeviceConnected(std::wstring remoteHostName) override;
    virtual void OnDeviceDisconnected(std::wstring deviceId) override;
    virtual void OnAdvertisementStarted() override;
    virtual void OnAdvertisementStopped(std::wstring message) override;
    virtual void OnAdvertisementAborted(std::wstring message) override;
    virtual void OnAsyncException(std::wstring message) override;
    virtual void LogMessage(std::wstring message) override;
};
