#pragma once
#include "lwip_includes.h"

// Callback for LwIP when a new connection comes in
err_t tcp_proxy_accept(void* arg, struct tcp_pcb* newpcb, err_t err);
