#pragma once
#include <cstdint>

// Initialize/Check timeouts for UDP sessions
void udp_check_timeouts();
void handle_udp_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t* payload, int len);