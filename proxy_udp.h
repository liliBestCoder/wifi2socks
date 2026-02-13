#pragma once

#include <winsock2.h>
#include "nat_manager.h" // For OriginalDestination

class UdpProxy {
public:
    // The main entry point for handling UDP packets from the AppListener.
    // It manages outgoing sockets and routes responses back to the correct client.
    static void handle_client_data(
        SOCKET listener_socket,
        const char* data,
        int len,
        const sockaddr_in* client_addr,
        const OriginalDestination* dest
    );

    // Initializes the UDP proxy manager.
    static void initialize();

    // Stops the UDP proxy manager and cleans up resources.
    static void shutdown();
};