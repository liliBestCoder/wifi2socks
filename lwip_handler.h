#pragma once
#include <mutex>
#include <cstdint>
#include "lwip_includes.h"

class WinPkFilterDriver;
extern WinPkFilterDriver* g_winpkfilter_driver;

class DhcpServer;
extern DhcpServer* g_dhcp_server_ptr;

uint32_t get_now_ms();
void lwip_system_init();
void lwip_periodic_handle();
void process_ethernet_frame(const char* packet, size_t length, bool outbound);
void set_winpkfilter_driver(WinPkFilterDriver* driver);

// Helpers
uint16_t ip_chksum_simple(void* dataptr, int len);
void recalculate_tcp_checksum(struct ip_hdr* ip, uint8_t* tcp_base, int tcp_len);

extern struct netif g_netif;
extern uint8_t HOST_MAC[6];
extern bool g_host_mac_known;

// Callback for LwIP when a new connection comes in
err_t tcp_proxy_accept(void* arg, struct tcp_pcb* newpcb, err_t err);

err_t netif_init_cb(struct netif* netif);
