#include "utils.h"

void print_mac(const uint8_t* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint32_t ip) {
    ip = ntohl(ip);
    printf("%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

uint16_t checksum(const void* p, int len, uint32_t c) {
    const uint16_t* buf = (const uint16_t*)p;
    for (; len > 1; len -= 2) c += *buf++;
    if (len == 1) c += *(const uint8_t*)buf;
    while (c >> 16) c = (c & 0xffff) + (c >> 16);
    return ~uint16_t(c);
}

uint16_t tcp_cksum(uint32_t s, uint32_t d, const uint8_t* tcp, int len) {
    struct PH { uint32_t s, d; uint8_t zero, proto; uint16_t len; } ph = { s,d,0,6,htons((uint16_t)len) };
    uint32_t sum = checksum(&ph, sizeof(ph), 0);
    return checksum(tcp, len, sum);
}

uint16_t udp_cksum(uint32_t s, uint32_t d, const uint8_t* udp, int len) {
    struct PH { uint32_t s, d; uint8_t zero, proto; uint16_t len; } ph = { s,d,0,17,htons((uint16_t)len) };
    uint32_t sum = checksum(&ph, sizeof(ph), 0);
    return checksum(udp, len, sum);
}

void platform_send_frame(HANDLE tap, const uint8_t* f, int len) {
    DWORD w; WriteFile(tap, f, len, &w, NULL);
}