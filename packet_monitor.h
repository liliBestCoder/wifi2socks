#pragma once

#include <windows.h>
#include <vector>
#include <mutex>
#include <thread>
#include <string>
#include <atomic>

// PCAP file structures
struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type (1 for Ethernet) */
};

struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

class PacketMonitor {
public:
    static PacketMonitor& instance();

    void start(const std::string& pipe_name = "\.\pipe\wifi2socks_monitor");
    void stop();
    void publish(const char* data, size_t len);

private:
    PacketMonitor();
    ~PacketMonitor();

    void listen_thread();
    void broadcast_header(HANDLE pipe);

    std::string m_pipe_name;
    std::vector<HANDLE> m_clients;
    std::mutex m_mutex;
    std::thread m_listen_thread;
    std::atomic<bool> m_running;
};
