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
#define PBUF_POOL_SIZE                  512  // Increased for streaming
#define PBUF_POOL_BUFSIZE               2048 // Large enough for MTU + Headers

// --- 4. TCP/IP ---
#define LWIP_TCP                        1
#define TCP_MSS                         1460  // Adjusted for Ethernet MTU
#define TCP_WND                         (512 * 1024)   // 512KB window for high throughput
#define TCP_SND_BUF                     (4096 * 1024) // 512KB for HD streaming
#define TCP_SNDLOWAT                    (32 * 1024)  // Fixed: Prevent u16_t overflow with large SND_BUF
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   4     // Scale 4 (x16) -> 1MB Max Window

#define LWIP_ARP                        1
#define LWIP_ETHERNET                   1
#define LWIP_IPV4                       1
#define IP_FORWARD                      0

// --- 5. OPTIMIZATIONS ---
#define CHECKSUM_CHECK_IP               0
#define CHECKSUM_CHECK_UDP              0
#define CHECKSUM_CHECK_TCP              0
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_GEN_TCP                1

// --- 6. PLATFORM ---
// Let LwIP define its own types for its core files
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 0
#define LWIP_TIMEVAL_PRIVATE 1

// We do NOT include winsock2.h here to protect ip4_addr.c from macro pollution 
#endif