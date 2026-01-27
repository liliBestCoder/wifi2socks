#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

#include <winsock2.h> // Prevent winsock.h conflicts in LwIP sources

// --- System ---
#define NO_SYS                          1  // No OS mode (Main loop)
#define SYS_LIGHTWEIGHT_PROT            0  // Not needed for NO_SYS
#define LWIP_TIMERS                     1

// --- Memory ---
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_ALIGNMENT                   4

// --- TCP ---
#define LWIP_TCP                        1
#define TCP_MSS                         1400
#define TCP_WND                         (32 * TCP_MSS) // Increase window for speed
#define TCP_SND_BUF                     (32 * TCP_MSS)
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   2

// --- ARP ---
#define LWIP_ARP                        1
#define LWIP_ETHERNET                   1

// --- IP ---
#define LWIP_IPV4                       1
#define IP_FORWARD                      0

// --- Checksums ---
// Disable checksum checks for performance (Virtual interface is reliable)
#define CHECKSUM_CHECK_IP               0
#define CHECKSUM_CHECK_UDP              0
#define CHECKSUM_CHECK_TCP              0
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_GEN_TCP                1

// --- Debugging (Optional) ---
// #define LWIP_DEBUG                      1
// #define TCP_DEBUG                       LWIP_DBG_ON

#endif
