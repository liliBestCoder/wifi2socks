#ifndef UTILS_H
#define UTILS_H

#include <cstdint>
#include <ws2tcpip.h>
#include <stdio.h>
#include "packet.h"

void print_mac(const uint8_t* mac);
void print_ip(uint32_t ip);

uint16_t checksum(const void* p, int len, uint32_t c = 0);
uint16_t tcp_cksum(uint32_t s, uint32_t d, const uint8_t* tcp, int len);
uint16_t udp_cksum(uint32_t s, uint32_t d, const uint8_t* udp, int len);

// SOCKS5 Configuration
#define SOCKS_SERVER_IP "127.0.0.1"
#define SOCKS_SERVER_PORT 2080

#include <windows.h>
void platform_send_frame(HANDLE tap, const uint8_t* f, int len);

#endif