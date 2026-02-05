#include "wifi_ap_listener.h"
#include "app_config.h"

void Wifi2SocksWiFiListener::OnDeviceConnected(std::wstring remoteHostName) {
    LOG_INFO("[WIFI ] Device Connected: %ls\n", remoteHostName.c_str());
}

void Wifi2SocksWiFiListener::OnDeviceDisconnected(std::wstring deviceId) {
    LOG_INFO("[WIFI ] Device Disconnected: %ls\n", deviceId.c_str());
}

void Wifi2SocksWiFiListener::OnAdvertisementStarted() {
    LOG_INFO("[WIFI ] Advertisement Started.\n");
}

void Wifi2SocksWiFiListener::OnAdvertisementStopped(std::wstring message) {
    LOG_INFO("[WIFI ] Advertisement Stopped: %ls\n", message.c_str());
}

void Wifi2SocksWiFiListener::OnAdvertisementAborted(std::wstring message) {
    LOG_INFO("[WIFI ] Advertisement Aborted: %ls\n", message.c_str());
}

void Wifi2SocksWiFiListener::OnAsyncException(std::wstring message) {
    LOG_INFO("[WIFI ] Error: %ls\n", message.c_str());
}

void Wifi2SocksWiFiListener::LogMessage(std::wstring message) {
    LOG_INFO("[WIFI ] %ls\n", message.c_str());
}

