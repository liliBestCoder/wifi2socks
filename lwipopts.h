#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

// --- 1. SYSTEM MODE ---
#define NO_SYS                          1  // Raw API mode
#define SYS_LIGHTWEIGHT_PROT            0 
#define LWIP_TIMERS                     1

// --- 2. DISABLE CONFLICTING APIs ---
#define LWIP_SOCKET                     0  // Disable Sockets (We use Windows sockets for Proxy)
#define LWIP_NETCONN                    0  // Disable Netconn
#define LWIP_SEQUENTIAL_API             0

// --- 3. MEMORY ---
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_ALIGNMENT                   4
#define PBUF_POOL_SIZE                  4096 // Double the pool for high concurrency
#define PBUF_POOL_BUFSIZE               2048 // Large enough for MTU + Headers

// --- 4. TCP/IP ---
#define LWIP_TCP                        1
#define TCP_INITIAL_CWND                10
#define TCP_MSS                         1300
#define TCP_WND                         (65535UL << 5)
#define TCP_SND_BUF                     (4*1024*1024)
#define TCP_SND_QUEUELEN                6552
#define TCP_SNDLOWAT                    (32*1024)
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   5

#define LWIP_ARP                        1
#define LWIP_ETHERNET                   1
#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define LWIP_RAW                        1
#define IP_FORWARD                      1
#define ETHARP_SUPPORT_STATIC_ENTRIES   1

// --- 5. OPTIMIZATIONS ---
#define CHECKSUM_CHECK_IP               0
#define CHECKSUM_CHECK_UDP              0
#define CHECKSUM_CHECK_TCP              0
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_GEN_TCP                1

// --- 6. DEBUGGING ---
#define LWIP_DEBUG                      1
#define IP_DEBUG                        LWIP_DBG_ON
#define RAW_DEBUG                       LWIP_DBG_ON
#define UDP_DEBUG                       LWIP_DBG_ON
#define NETIF_DEBUG                     LWIP_DBG_ON

// --- 7. PLATFORM ---
// Let LwIP define its own types for its core files
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 0
#define LWIP_TIMEVAL_PRIVATE 1

// We do NOT include winsock2.h here to protect ip4_addr.c from macro pollution 
#endif