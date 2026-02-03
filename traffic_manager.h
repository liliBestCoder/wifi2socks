#pragma once
#include <cstdint>
#include <atomic>
#include <thread>
#include <string>

class TrafficManager {
public:
    static TrafficManager& instance();

    // Stats Reporting
    void report_tap_tx(uint32_t bytes); // Upload (From User)
    void report_tap_rx(uint32_t bytes); // Download (To User)
    void report_proxy_tx(uint32_t bytes); // Upload (To Proxy)
    void report_proxy_rx(uint32_t bytes); // Download (From Proxy)

    // Start background services
    void start();
    void stop();

private:
    TrafficManager();
    ~TrafficManager();

    // Counters (Total)
    std::atomic<uint64_t> m_tap_tx_total{0};
    std::atomic<uint64_t> m_tap_rx_total{0};
    std::atomic<uint64_t> m_proxy_tx_total{0};
    std::atomic<uint64_t> m_proxy_rx_total{0};

    // Speed (Bytes/sec)
    std::atomic<uint64_t> m_tap_tx_speed{0};
    std::atomic<uint64_t> m_tap_rx_speed{0};
    std::atomic<uint64_t> m_proxy_tx_speed{0};
    std::atomic<uint64_t> m_proxy_rx_speed{0};

    // Workers
    std::thread m_speed_thread;
    std::atomic<bool> m_running{false};

    void speed_loop();
    
    // API
    std::string get_json_stats();
};
