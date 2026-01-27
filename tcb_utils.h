#pragma once
#include "tcb.h"
#include "packet.h"
#include <windows.h>

// Forward declaration to avoid circular dependency
struct TCB;

void process_tcp_packet(TCB& tcb, const Packet& pkt, HANDLE tap);
void flush_output(TCB& tcb, HANDLE tap);
