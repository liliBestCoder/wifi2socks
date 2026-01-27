#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

// --- 1. PREVENT WINDOWS HEADER CONFLICTS ---
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

// Tell LwIP that we rely on system headers for these
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#define LWIP_TIMEVAL_PRIVATE 0 
#define LWIP_ERRNO_INCLUDE <errno.h>

// --- 2. SYSTEM MODE ---
#define NO_SYS                          1  // Raw API mode (Single threaded)
#define SYS_LIGHTWEIGHT_PROT            0 
#define LWIP_TIMERS                     1

// --- 3. DISABLE UNUSED APIs (FIXES COMPILE ERRORS) ---
#define LWIP_SOCKET                     0  // Disable Sockets API (Requires OS)
#define LWIP_NETCONN                    0  // Disable Netconn API (Requires OS)
#define LWIP_SEQUENTIAL_API             0

// --- 4. MEMORY ---
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_ALIGNMENT                   4

// --- 5. TCP/IP ---
#define LWIP_TCP                        1
#define TCP_MSS                         1400
#define TCP_WND                         (32 * TCP_MSS) 
#define TCP_SND_BUF                     (32 * TCP_MSS)
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   2

#define LWIP_ARP                        1
#define LWIP_ETHERNET                   1
#define LWIP_IPV4                       1
#define IP_FORWARD                      0

// --- 6. OPTIMIZATIONS ---
// Disable checksum checking since TAP interface is virtual/reliable
#define CHECKSUM_CHECK_IP               0
#define CHECKSUM_CHECK_UDP              0
#define CHECKSUM_CHECK_TCP              0
// Enable generation because peers need valid checksums
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_GEN_TCP                1

#endif