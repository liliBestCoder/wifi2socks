#ifndef UCB_H
#define UCB_H
#include <ws2tcpip.h>
#include <cstdint>
#include <vector>
#include "packet.h"

struct UCB {
    Quad quad;
    SOCKET udpSock; 
    
    UCB(const Quad& q) : quad(q), udpSock(INVALID_SOCKET) {}
};

#endif