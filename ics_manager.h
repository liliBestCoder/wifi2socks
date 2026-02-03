#pragma once
#include <string>
#include <windows.h>
#include <netcon.h>
#include <wrl/client.h> // Use WRL ComPtr instead of ATL

class IcsManager {
public:
    static bool EnableICS(const std::wstring& publicAdapterName, const std::wstring& privateAdapterDesc);

private:
    static bool SetConnectionSharing(INetSharingManager* pNSM, INetConnection* pConnection, SHARING_CONNECTION_TYPE type);
};