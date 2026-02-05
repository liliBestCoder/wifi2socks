#pragma once
#include <mutex>
#include <cstdint>
#include "lwip_includes.h"

// Global LwIP lock
extern std::recursive_mutex g_lwip_mtx;

uint32_t get_now_ms();
void lwip_system_init();
void lwip_periodic_handle();
void process_tap_frame(uint8_t* buf, int len);

// Helpers
uint16_t ip_chksum_simple(void* dataptr, int len);

extern struct netif g_netif;
extern uint8_t HOST_MAC[6];
extern bool g_host_mac_known;

// Callback for LwIP when a new connection comes in
err_t tcp_proxy_accept(void* arg, struct tcp_pcb* newpcb, err_t err);

err_t netif_init_cb(struct netif* netif);
