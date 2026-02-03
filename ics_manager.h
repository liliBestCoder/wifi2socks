#pragma once
#include <string>
#include <windows.h>
#include <wrl/client.h> 

// Forward declarations to avoid including netcon.h header dependency
struct INetSharingManager;
struct INetConnection;

class IcsManager {
public:
    // Enables ICS. 
    static bool EnableICS(const std::wstring& publicAdapterName, const std::wstring& privateAdapterDesc);

private:
    static bool SetConnectionSharing(INetSharingManager* pNSM, INetConnection* pConnection, int type);
};
