#pragma once

#include <winsock2.h>
#include <lwip/err.h>
#include <lwip/tcp.h>

err_t tcp_proxy_accept(void* arg, struct tcp_pcb* newpcb, err_t err);