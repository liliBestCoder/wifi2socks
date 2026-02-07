/*
 * WinDivert.h
 *
 * The main header file for the WinDivert driver.
 *
 * This file is part of the WinDivert package.
 *
 * Copyright (c) 2014-2021, Basil Pozniakov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __WINDIVERT_H__
#define __WINDIVERT_H__

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Divert address.
 *
 * The divert address is used to indicate the network interface, packet
 * direction, and other properties.
 */
typedef struct
{
    INT64  Timestamp;           /* Packet's timestamp. */
    UINT32 IfIdx;               /* Inbound network interface index. */
    UINT32 SubIfIdx;            /* Inbound network sub-interface index. */
    UINT8  Direction;           /* Packet's direction. */
} WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;

/*
 * Packet direction is from the following enum.
 */
typedef enum
{
    WINDIVERT_DIRECTION_OUTBOUND,   /* Outbound packet. */
    WINDIVERT_DIRECTION_INBOUND     /* Inbound packet. */
} WINDIVERT_DIRECTION;

/*
 * The maximum length of a filter string.
 */
#define WINDIVERT_MAX_FILTER_LENGTH         4095

/*
 * The maximum length of a packet.
 */
#define WINDIVERT_MTU                       65535

/*
 * Divert layer is one of the following.
 *
 * The default layer is WINDIVERT_LAYER_NETWORK.
 */
typedef enum
{
    WINDIVERT_LAYER_NETWORK_FORWARD, /* Network layer with IP forwarding. */
    WINDIVERT_LAYER_NETWORK,         /* Network layer. */
    WINDIVERT_LAYER_FLOW,            /* Flow layer. */
    WINDIVERT_LAYER_SOCKET,          /* Socket layer. */
    WINDIVERT_LAYER_REFLECT          /* Reflect layer. */
} WINDIVERT_LAYER;

/*
 * Divert priority is a 31-bit signed integer in the range
 * WINDIVERT_PRIORITY_LOWEST to WINDIVERT_PRIORITY_HIGHEST.
 *
 * The default priority is 0.
 */
#define WINDIVERT_PRIORITY_HIGHEST          10000
#define WINDIVERT_PRIORITY_HIGH             5000
#define WINDIVERT_PRIORITY_NORMAL           0
#define WINDIVERT_PRIORITY_LOW              -5000
#define WINDIVERT_PRIORITY_LOWEST           -10000

/*
 * Divert flags are zero or more of the following.
 *
 * The default is 0.
 */
#define WINDIVERT_FLAG_SNIFF                0x0001
#define WINDIVERT_FLAG_DROP                 0x0002
#define WINDIVERT_FLAG_RECV_ONLY            0x0004
#define WINDIVERT_FLAG_SEND_ONLY            0x0008
#define WINDIVERT_FLAG_NO_INSTALL           0x0010
#define WINDIVERT_FLAG_FRAGMENTS            0x0020
#define WINDIVERT_FLAG_READ_ONLY            WINDIVERT_FLAG_RECV_ONLY

/*
 * Divert parameters are one of the following.
 */
typedef enum
{
    WINDIVERT_PARAM_QUEUE_LEN,          /* Packet queue length. */
    WINDIVERT_PARAM_QUEUE_TIME          /* Packet queue time. */
} WINDIVERT_PARAM;

/*
 * The maximum length of a divert parameter.
 */
#define WINDIVERT_PARAM_MAX_LENGTH          ((UINT)0xFFFFFFFF)

/*
 * Socket/flow flags are zero or more of the following.
 */
#define WINDIVERT_FLAG_HALF_OPEN            0x0001
#define WINDIVERT_FLAG_HALF_CLOSE           0x0002
#define WINDIVERT_FLAG_PROXY_CLOSED         0x0004

/*
 * Open a divert handle.
 */
HANDLE WinDivertOpen(
    __in        LPCSTR filter,
    __in        WINDIVERT_LAYER layer,
    __in        INT16 priority,
    __in        UINT64 flags
    );

/*
 * Receive (read) a packet from a divert handle.
 */
BOOL WinDivertRecv(
    __in        HANDLE handle,
    __out_opt   PVOID pPacket,
    __in        UINT packetLen,
    __out_opt   WINDIVERT_ADDRESS *pAddr,
    __out_opt   UINT *readLen
    );

/*
 * Receive (read) a packet from a divert handle.
 */
BOOL WinDivertRecvEx(
    __in        HANDLE handle,
    __out_opt   PVOID pPacket,
    __in        UINT packetLen,
    __in        UINT64 flags,
    __out_opt   WINDIVERT_ADDRESS *pAddr,
    __out_opt   UINT *readLen,
    __inout_opt LPOVERLAPPED lpOverlapped
    );

/*
 * Send (write) a packet to a divert handle.
 */
BOOL WinDivertSend(
    __in        HANDLE handle,
    __in        PVOID pPacket,
    __in        UINT packetLen,
    __in        const WINDIVERT_ADDRESS *pAddr,
    __out_opt   UINT *writeLen
    );

/*
 * Send (write) a packet to a divert handle.
 */
BOOL WinDivertSendEx(
    __in        HANDLE handle,
    __in        PVOID pPacket,
    __in        UINT packetLen,
    __in        UINT64 flags,
    __in        const WINDIVERT_ADDRESS *pAddr,
    __out_opt   UINT *writeLen,
    __inout_opt LPOVERLAPPED lpOverlapped
    );

/*
 * Close a divert handle.
 */
BOOL WinDivertClose(
    __in        HANDLE handle
    );

/*
 * Set a divert handle parameter.
 */
BOOL WinDivertSetParam(
    __in        HANDLE handle,
    __in        WINDIVERT_PARAM param,
    __in        UINT64 value
    );

/*
 * Get a divert handle parameter.
 */
BOOL WinDivertGetParam(
    __in        HANDLE handle,
    __in        WINDIVERT_PARAM param,
    __out       UINT64 *pValue
    );

/*
 * Helper functions for parsing IPv4/IPv6/ICMP/ICMPv6/TCP/UDP headers.
 */
typedef struct
{
    UINT8  Version;             /* IP version. */
    UINT8  HdrLength;           /* IP header length. */
    UINT16 Length;              /* IP packet length. */
    UINT16 Id;                  /* IP ID. */
    UINT16 FragOff0;            /* Fragment offset and flags. */
    UINT8  TTL;                 /* Time to live. */
    UINT8  Protocol;            /* Protocol. */
    UINT16 Checksum;            /* Header checksum. */
    UINT32 SrcAddr;             /* Source address. */
    UINT32 DstAddr;             /* Destination address. */
} WINDIVERT_IPHDR, *PWINDIVERT_IPHDR;

typedef struct
{
    UINT32 Version;             /* IP version. */
    UINT16 Length;              /* Payload length. */
    UINT8  NextHdr;             /* Next header. */
    UINT8  HopLimit;            /* Hop limit. */
    UINT32 SrcAddr[4];          /* Source address. */
    UINT32 DstAddr[4];          /* Destination address. */
} WINDIVERT_IPV6HDR, *PWINDIVERT_IPV6HDR;

typedef struct
{
    UINT8  Type;                /* Message type. */
    UINT8  Code;                /* Message code. */
    UINT16 Checksum;            /* Checksum of the message. */
    UINT32 Body;                /* Message body. */
} WINDIVERT_ICMPHDR, *PWINDIVERT_ICMPHDR;

typedef struct
{
    UINT8  Type;                /* Message type. */
    UINT8  Code;                /* Message code. */
    UINT16 Checksum;            /* Checksum of the message. */
    UINT32 Body;                /* Message body. */
} WINDIVERT_ICMPV6HDR, *PWINDIVERT_ICMPV6HDR;

typedef struct
{
    UINT16 SrcPort;             /* Source port. */
    UINT16 DstPort;             /* Destination port. */
    UINT32 SeqNum;              /* Sequence number. */
    UINT32 AckNum;              /* Acknowledgment number. */
    UINT16 HdrLength;           /* Header length. */
    UINT16 Reserved1;           /* Reserved. */
    UINT16 Fin;                 /* Fin flag. */
    UINT16 Syn;                 /* Syn flag. */
    UINT16 Rst;                 /* Rst flag. */
    UINT16 Psh;                 /* Psh flag. */
    UINT16 Ack;                 /* Ack flag. */
    UINT16 Urg;                 /* Urg flag. */
    UINT16 Ece;                 /* Ece flag. */
    UINT16 Cwr;                 /* Cwr flag. */
    UINT16 Ns;                  /* Ns flag. */
    UINT16 Reserved2;           /* Reserved. */
    UINT16 Window;              /* Window size. */
    UINT16 Checksum;            /* Header checksum. */
    UINT16 UrgPtr;              /* Urgent pointer. */
} WINDIVERT_TCPHDR, *PWINDIVERT_TCPHDR;

typedef struct
{
    UINT16 SrcPort;             /* Source port. */
    UINT16 DstPort;             /* Destination port. */
    UINT16 Length;              /* UDP length. */
    UINT16 Checksum;            /* UDP checksum. */
} WINDIVERT_UDPHDR, *PWINDIVERT_UDPHDR;

/*
 * DEPRECATED: use WINDIVERT_IPHDR_GET_VER, WINDIVERT_IPHDR_GET_HLEN, etc.,
 * instead.
 */
#define WINDIVERT_IPHDR_V(hdr)              (((hdr)->Version & 0xF0) >> 4)
#define WINDIVERT_IPHDR_HL(hdr)             ((hdr)->Version & 0x0F)
#define WINDIVERT_IPHDR_SET_V(hdr, val)     ((hdr)->Version = 
                                                (((val) << 4) | ((hdr)->Version & 0x0F)))
#define WINDIVERT_IPHDR_SET_HL(hdr, val)    ((hdr)->Version = 
                                                ((val) | ((hdr)->Version & 0xF0)))

#define WINDIVERT_IPHDR_MF(hdr)             (ntohs((hdr)->FragOff0) & 0x2000)
#define WINDIVERT_IPHDR_FO(hdr)             (ntohs((hdr)->FragOff0) & 0x1FFF)
#define WINDIVERT_IPHDR_SET_MF(hdr, val)    ((hdr)->FragOff0 = 
                                                htons((val)? (ntohs((hdr)->FragOff0) | 0x2000) : (ntohs((hdr)->FragOff0) & 0xDFFF)))
#define WINDIVERT_IPHDR_SET_FO(hdr, val)    ((hdr)->FragOff0 = 
                                                htons(((val) & 0x1FFF) | (ntohs((hdr)->FragOff0) & 0xE000)))

#define WINDIVERT_IPV6HDR_V(hdr)            (((hdr)->Version & 0xF0000000) >> 28)
#define WINDIVERT_IPV6HDR_TC(hdr)           ((ntohl((hdr)->Version) & 0x0FF00000) >> 20)
#define WINDIVERT_IPV6HDR_FL(hdr)           (ntohl((hdr)->Version) & 0x000FFFFF)
#define WINDIVERT_IPV6HDR_SET_V(hdr, val)   ((hdr)->Version = 
                                                (htonl((val) << 28) | ((hdr)->Version & 0x0FFFFFFF)))
#define WINDIVERT_IPV6HDR_SET_TC(hdr, val)  ((hdr)->Version = 
                                                (htonl(((val) & 0xFF) << 20) | ((hdr)->Version & 0xF00FFFFF)))
#define WINDIVERT_IPV6HDR_SET_FL(hdr, val)  ((hdr)->Version = 
                                                (htonl((val) & 0xFFFFF) | ((hdr)->Version & 0xFFF00000)))

#define WINDIVERT_TCPHDR_HL(hdr)            (((hdr)->HdrLength & 0xF000) >> 12)
#define WINDIVERT_TCPHDR_SET_HL(hdr, val)   ((hdr)->HdrLength = 
                                                htons((((val) & 0x0F) << 12) | ntohs((hdr)->HdrLength & 0x0FFF)))
#define WINDIVERT_TCPHDR_FIN(hdr)           (((hdr)->Reserved1 & 0x0100))
#define WINDIVERT_TCPHDR_SYN(hdr)           (((hdr)->Reserved1 & 0x0200))
#define WINDIVERT_TCPHDR_RST(hdr)           (((hdr)->Reserved1 & 0x0400))
#define WINDIVERT_TCPHDR_PSH(hdr)           (((hdr)->Reserved1 & 0x0800))
#define WINDIVERT_TCPHDR_ACK(hdr)           (((hdr)->Reserved1 & 0x1000))
#define WINDIVERT_TCPHDR_URG(hdr)           (((hdr)->Reserved1 & 0x2000))
#define WINDIVERT_TCPHDR_ECE(hdr)           (((hdr)->Reserved1 & 0x4000))
#define WINDIVERT_TCPHDR_CWR(hdr)           (((hdr)->Reserved1 & 0x8000))
#define WINDIVERT_TCPHDR_NS(hdr)            (((hdr)->Reserved2 & 0x0100))
#define WINDIVERT_TCPHDR_SET_FIN(hdr, val)  ((hdr)->Reserved1 = 
                                                htons((val)? (ntohs((hdr)->Reserved1) | 0x0100) : (ntohs((hdr)->Reserved1) & 0xFEFF)))
#define WINDIVERT_TCPHDR_SET_SYN(hdr, val)  ((hdr)->Reserved1 = 
                                                htons((val)? (ntohs((hdr)->Reserved1) | 0x0200) : (ntohs((hdr)->Reserved1) & 0xFDFF)))
#define WINDIVERT_TCPHDR_SET_RST(hdr, val)  ((hdr)->Reserved1 = 
                                                htons((val)? (ntohs((hdr)->Reserved1) | 0x0400) : (ntohs((hdr)->Reserved1) & 0xFBFF)))
#define WINDIVERT_TCPHDR_SET_PSH(hdr, val)  ((hdr)->Reserved1 = 
                                                htons((val)? (ntohs((hdr)->Reserved1) | 0x0800) : (ntohs((hdr)->Reserved1) & 0xF7FF)))
#define WINDIVERT_TCPHDR_SET_ACK(hdr, val)  ((hdr)->Reserved1 = 
                                                htons((val)? (ntohs((hdr)->Reserved1) | 0x1000) : (ntohs((hdr)->Reserved1) & 0xEFFF)))
#define WINDIVERT_TCPHDR_SET_URG(hdr, val)  ((hdr)->Reserved1 = 
                                                htons((val)? (ntohs((hdr)->Reserved1) | 0x2000) : (ntohs((hdr)->Reserved1) & 0xDFFF)))
#define WINDIVERT_TCPHDR_SET_ECE(hdr, val)  ((hdr)->Reserved1 = 
                                                htons((val)? (ntohs((hdr)->Reserved1) | 0x4000) : (ntohs((hdr)->Reserved1) & 0xBFFF)))
#define WINDIVERT_TCPHDR_SET_CWR(hdr, val)  ((hdr)->Reserved1 = 
                                                htons((val)? (ntohs((hdr)->Reserved1) | 0x8000) : (ntohs((hdr)->Reserved1) & 0x7FFF)))
#define WINDIVERT_TCPHDR_SET_NS(hdr, val)   ((hdr)->Reserved2 = 
                                                htons((val)? (ntohs((hdr)->Reserved2) | 0x0100) : (ntohs((hdr)->Reserved2) & 0xFEFF)))

BOOL WinDivertHelperParsePacket(
    __in        PVOID pPacket,
    __in        UINT packetLen,
    __out_opt   PWINDIVERT_IPHDR *ppIpHdr,
    __out_opt   PWINDIVERT_IPV6HDR *ppIpv6Hdr,
    __out_opt   UINT8 *pProtocol,
    __out_opt   PWINDIVERT_ICMPHDR *ppIcmpHdr,
    __out_opt   PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    __out_opt   PWINDIVERT_TCPHDR *ppTcpHdr,
    __out_opt   PWINDIVERT_UDPHDR *ppUdpHdr,
    __out_opt   PVOID *ppData,
    __out_opt   UINT *pDataLen
    );

BOOL WinDivertHelperParseIPv4Address(
    __in        LPCSTR addrStr,
    __out       UINT32 *pAddr
    );

BOOL WinDivertHelperParseIPv6Address(
    __in        LPCSTR addrStr,
    __out       UINT32 *pAddr
    );

BOOL WinDivertHelperFormatIPv4Address(
    __in        UINT32 addr,
    __out       PCHAR addrStr,
    __in        UINT addrStrLen
    );

BOOL WinDivertHelperFormatIPv6Address(
    __in        const UINT32 *pAddr,
    __out       PCHAR addrStr,
    __in        UINT addrStrLen
    );

UINT16 WinDivertHelperCalcChecksums(
    __inout     PVOID pPacket,
    __in        UINT packetLen,
    __in        UINT64 flags
    );

#define WINDIVERT_HELPER_NO_IP_CHECKSUM         0x0001
#define WINDIVERT_HELPER_NO_ICMP_CHECKSUM       0x0002
#define WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM     0x0004
#define WINDIVERT_HELPER_NO_TCP_CHECKSUM        0x0008
#define WINDIVERT_HELPER_NO_UDP_CHECKSUM        0x0010

/*
 * DEPRECATED: use WINDIVERT_HELPER_NO_IP_CHECKSUM instead.
 */
#define WINDIVERT_HELPER_IP_CHECKSUM            0x0001
/*
 * DEPRECATED: use WINDIVERT_HELPER_NO_TCP_CHECKSUM instead.
 */
#define WINDIVERT_HELPER_TCP_CHECKSUM           0x0002
/*
 * DEPRECATED: use WINDIVERT_HELPER_NO_UDP_CHECKSUM instead.
 */
#define WINDIVERT_HELPER_UDP_CHECKSUM           0x0004

UINT16 WinDivertHelperCalcChecksumsForSend(
    __inout     PVOID pPacket,
    __in        UINT packetLen,
    __inout     PWINDIVERT_ADDRESS pAddr,
    __in        UINT64 flags
    );

BOOL WinDivertHelperGetOption(
    __in        PVOID pPacket,
    __in        UINT packetLen,
    __in        UINT8 protocol,
    __in        UINT8 option,
    __out       PVOID *ppData,
    __out       UINT *pDataLen
    );

PVOID WinDivertHelperFindOption(
    __in        PVOID pPacket,
    __in        UINT packetLen,
    __in        UINT8 protocol,
    __in        UINT8 option
    );

BOOL WinDivertHelperEvalFilter(
    __in        PCSTR filter,
    __in        PVOID pPacket,
    __in        UINT packetLen,
    __in        const WINDIVERT_ADDRESS *pAddr
    );

#ifdef __cplusplus
}
#endif

#endif /* __WINDIVERT_H__ */
