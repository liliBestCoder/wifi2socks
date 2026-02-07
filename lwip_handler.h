#pragma once
#include <mutex>
#include <cstdint>
#include "lwip_includes.h"
#include "windivert.h"

// Global LwIP lock
extern std::recursive_mutex g_lwip_mtx;
extern WinDivertDriver* g_windivert_driver;
extern WINDIVERT_ADDRESS g_last_addr;

uint32_t get_now_ms();
void lwip_system_init();
void lwip_periodic_handle();
void process_ip_packet(const char* buf, int len, const void* addr);
void set_windivert_driver(WinDivertDriver* driver);

// Helpers
uint16_t ip_chksum_simple(void* dataptr, int len);
void recalculate_tcp_checksum(struct ip_hdr* ip, uint8_t* tcp_base, int tcp_len);

extern struct netif g_netif;
extern uint8_t HOST_MAC[6];
extern bool g_host_mac_known;

// Callback for LwIP when a new connection comes in
err_t tcp_proxy_accept(void* arg, struct tcp_pcb* newpcb, err_t err);

err_t netif_init_cb(struct netif* netif);
