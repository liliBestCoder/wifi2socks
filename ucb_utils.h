#pragma once
#include <windows.h>
#include "ucb.h"
#include "packet.h"

void process_udp_packet(UCB& ucb, const Packet& pkt, HANDLE tap);