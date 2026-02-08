/*************************************************************************/
/*                    Copyright (c) 2000-2024 NT KERNEL.                 */
/*                           All Rights Reserved.                        */
/*                          https://www.ntkernel.com                     */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ndisapi.h                                               */
/*                                                                       */
/* Description: API exported C++ class and C API declarations            */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "Common.h"

#ifdef _LIB // must be defined when linking static library version of ndisapi.dll
#define NDISAPI_API 
#else
#ifdef NDISAPI_EXPORTS
#define NDISAPI_API __declspec(dllexport)
#else
#define NDISAPI_API __declspec(dllimport)
#endif //NDISAPI_EXPORTS
#endif //_LIB

#include <tchar.h>

class NDISAPI_API CNdisApi
{
public:
    CNdisApi(const TCHAR* pszFileName = _T(DRIVER_NAME_A));
    virtual ~CNdisApi();

    CNdisApi(const CNdisApi& other) = delete;
    CNdisApi& operator=(const CNdisApi& other) = delete;

public:
    // Driver services
    ULONG   GetVersion() const;
    BOOL    GetTcpipBoundAdaptersInfo(PTCP_AdapterList pAdapters) const;
    BOOL    SendPacketToMstcp(PETH_REQUEST pPacket) const;
    BOOL    SendPacketToAdapter(PETH_REQUEST pPacket) const;
    BOOL    ReadPacket(PETH_REQUEST pPacket) const;
    BOOL    SetAdapterMode(PADAPTER_MODE pMode) const;
    BOOL    SetPacketEvent(HANDLE hAdapter, HANDLE hWin32Event) const;
    BOOL    IsDriverLoaded() const;
};

extern "C"
{
    HANDLE  __stdcall        OpenFilterDriver(const TCHAR* pszFileName = _T(DRIVER_NAME_A));
    VOID    __stdcall        CloseFilterDriver(HANDLE hOpen);
    BOOL    __stdcall        GetTcpipBoundAdaptersInfo(HANDLE hOpen, PTCP_AdapterList pAdapters);
    BOOL    __stdcall        SendPacketToMstcp(HANDLE hOpen, PETH_REQUEST pPacket);
    BOOL    __stdcall        SendPacketToAdapter(HANDLE hOpen, PETH_REQUEST pPacket);
    BOOL    __stdcall        ReadPacket(HANDLE hOpen, PETH_REQUEST pPacket);
    BOOL    __stdcall        SetAdapterMode(HANDLE hOpen, PADAPTER_MODE pMode);
    BOOL    __stdcall        SetPacketEvent(HANDLE hOpen, HANDLE hAdapter, HANDLE hWin32Event);
    BOOL    __stdcall        IsDriverLoaded(HANDLE hOpen);
}
