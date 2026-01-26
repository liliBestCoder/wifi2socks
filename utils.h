#include <cstdint>
#include <ws2tcpip.h>
#include <stdio.h>

void print_mac(const uint8_t* mac);
void print_ip(uint32_t ip);