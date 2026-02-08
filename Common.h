/**************************************************************************/
/*                   Copyright (c) 2000-2024 NT KERNEL.                   */
/*                           All Rights Reserved.                         */
/*                          https://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                          */
/*                                                                        */
/* Module Name:  common.h                                                 */
/*                                                                        */
/* Abstract: Definitions common to kernel-mode driver and Win32 app.      */
/*                                                                        */
/* Environment:                                                           */
/*   User mode, Kernel mode                                               */
/*                                                                        */
/* Description: This header file contains definitions and data structures */
/*              that are common to both the kernel-mode driver and the    */
/*              Win32 application. This includes constants, structure     */
/*              definitions, and function prototypes.                     */
/*                                                                        */
/**************************************************************************/

#ifndef COMMON_H
#define COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// The following definitions are used to customize the driver build
// In you would like to redefine these for the custom build do that in the user_settings.h file
#ifdef USER_NAMES
#include "user_settings.h"
#else

// Define NDISRD name once in both ASCII and Unicode formats
#define NDISRD_NAME_A "NDISRD"
#define NDISRD_NAME_U L"NDISRD"

// Define lowercase NDISRD name for registry paths
#define NDISRD_NAME_LOWER_A "ndisrd"
#define NDISRD_NAME_LOWER_U L"ndisrd"

// FILTER_FRIENDLY_NAME is the friendly name of the NDISRD filter
#define FILTER_FRIENDLY_NAME L"WinpkFilter NDIS LightWeight Filter"

// FILTER_UNIQUE_NAME is the unique name (GUID) of the NDISRD filter
#define FILTER_UNIQUE_NAME L"{CD75C963-E19F-4139-BC3B-14019EF72F19}"

#endif // USER_NAMES

#ifndef ANY_SIZE
#define ANY_SIZE 1
#endif

#define ADAPTER_NAME_SIZE 256
#define ADAPTER_LIST_SIZE 32
#define ETHER_ADDR_LENGTH 6
#define MAX_ETHER_FRAME 1514

// MSTCP_FLAG definitions
#define MSTCP_FLAG_SENT_TUNNEL 0x00000001
#define MSTCP_FLAG_RECV_TUNNEL 0x00000002
#define MSTCP_FLAG_SENT_LISTEN 0x00000004
#define MSTCP_FLAG_RECV_LISTEN 0x00000008
#define MSTCP_FLAG_FILTER_DIRECT 0x00000010

#ifndef MSTCP_FLAG_TUNNEL
#define MSTCP_FLAG_TUNNEL (MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL)
#endif

#ifndef MSTCP_FLAG_SENT_RECEIVE
#define MSTCP_FLAG_SENT_RECEIVE (MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL)
#endif

typedef struct _TCP_AdapterList
{
    DWORD           m_nAdapterCount;
    unsigned char   m_szAdapterNameList[ADAPTER_LIST_SIZE][ADAPTER_NAME_SIZE];
    HANDLE          m_nAdapterHandle[ADAPTER_LIST_SIZE];
    unsigned int    m_nAdapterMediumList[ADAPTER_LIST_SIZE];
    unsigned char   m_czCurrentAddress[ADAPTER_LIST_SIZE][ETHER_ADDR_LENGTH];
    unsigned short  m_usMTU[ADAPTER_LIST_SIZE];
} TCP_AdapterList, * PTCP_AdapterList;

typedef struct _ADAPTER_MODE
{
    HANDLE  hAdapterHandle;
    DWORD   dwFlags;
} ADAPTER_MODE, * PADAPTER_MODE;

typedef struct _ETH_REQUEST
{
    HANDLE      hAdapterHandle;
    struct
    {
        PVOID   Buffer; // Actually points to INTERMEDIATE_BUFFER
    } EthPacket;
} ETH_REQUEST, * PETH_REQUEST;

typedef struct _ETH_M_REQUEST
{
    HANDLE      hAdapterHandle;
    DWORD       dwPacketsNumber;
    DWORD       dwPacketsSuccess;
    struct
    {
        PVOID   Buffer;
    } EthPacket[ANY_SIZE];
} ETH_M_REQUEST, * PETH_M_REQUEST;

typedef struct _INTERMEDIATE_BUFFER
{
    LIST_ENTRY      m_qLink;
    DWORD           m_dwDeviceFlags;
    DWORD           m_Length;
    unsigned char   m_IBuffer[MAX_ETHER_FRAME];
} INTERMEDIATE_BUFFER, * PINTERMEDIATE_BUFFER;

// Packet device flags
#define PACKET_FLAG_ON_SEND    0x00000001
#define PACKET_FLAG_ON_RECEIVE 0x00000002

typedef struct _IP_SUBNET_V4
{
    struct in_addr  m_Ip;
    struct in_addr  m_IpMask;
} IP_SUBNET_V4, * PIP_SUBNET_V4;

typedef struct _IP_SUBNET_V6
{
    IN6_ADDR        m_Ip;
    IN6_ADDR        m_IpMask;
} IP_SUBNET_V6, * PIP_SUBNET_V6;

typedef struct _IP_RANGE_V4
{
    struct in_addr  m_StartIp;
    struct in_addr  m_EndIp;
} IP_RANGE_V4, * PIP_RANGE_V4;

typedef struct _IP_RANGE_V6
{
    IN6_ADDR        m_StartIp;
    IN6_ADDR        m_EndIp;
} IP_RANGE_V6, * PIP_RANGE_V6;

#define DRIVER_NAME_A "NDISRD"

#endif // COMMON_H
