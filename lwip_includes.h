#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

// --- CONFLICT RESOLUTION ---
#define timeval     lwip_timeval
#define fd_set      lwip_fd_set
#define in_addr     lwip_in_addr
#define sockaddr    lwip_sockaddr
#define sockaddr_in lwip_sockaddr_in
#define sockaddr_storage lwip_sockaddr_storage
#define linger      lwip_linger

#define htonl       lwip_htonl
#define ntohl       lwip_ntohl
#define htons       lwip_htons
#define ntohs       lwip_ntohs
#define inet_addr   lwip_inet_addr
#define inet_ntoa   lwip_inet_ntoa

#ifdef s_addr
#undef s_addr
#endif

extern "C" {
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/ip.h"
#include "lwip/timeouts.h"
#include "netif/etharp.h"
#include "lwip/inet_chksum.h"
err_t ethernet_input(struct pbuf *p, struct netif *netif);
}

#undef timeval
#undef fd_set
#undef in_addr
#undef sockaddr
#undef sockaddr_in
#undef sockaddr_storage
#undef linger
#undef htonl
#undef ntohl
#undef htons
#undef ntohs
#undef inet_addr
#undef inet_ntoa
