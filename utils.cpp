#include "utils.h"

/* ---- 公共工具 ---- */
void print_mac(const uint8_t* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint32_t ip) {
    ip = ntohl(ip);
    printf("%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}