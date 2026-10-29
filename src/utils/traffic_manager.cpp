#include "traffic_manager.h"
#include <windows.h>
#include <sstream>
#include <chrono>
#include <cstdio>

TrafficManager& TrafficManager::instance() {
    static TrafficManager inst;
    return inst;
}

TrafficManager::TrafficManager() {}

TrafficManager::~TrafficManager() {
    stop();
}

void TrafficManager::start() {
    if (m_running.exchange(true)) return;
    m_speed_thread = std::thread(&TrafficManager::speed_loop, this);
}

void TrafficManager::stop() {
    if (!m_running.exchange(false)) return;
    if (m_speed_thread.joinable()) m_speed_thread.join();
}

void TrafficManager::report_tap_tx(uint32_t bytes) { m_tap_tx_total += bytes; }
void TrafficManager::report_tap_rx(uint32_t bytes) { m_tap_rx_total += bytes; }

void TrafficManager::report_proxy_tx(uint32_t bytes, bool is_direct) {
    if (is_direct) m_direct_tx_total += bytes;
    else m_proxy_tx_total += bytes;
}

void TrafficManager::report_proxy_rx(uint32_t bytes, bool is_direct) {
    if (is_direct) m_direct_rx_total += bytes;
    else m_proxy_rx_total += bytes;
}

void TrafficManager::speed_loop() {
    uint64_t last_tap_tx = 0, last_tap_rx = 0;
    uint64_t last_proxy_tx = 0, last_proxy_rx = 0;
    uint64_t last_direct_tx = 0, last_direct_rx = 0;
    
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        uint64_t cur_tap_tx = m_tap_tx_total;
        uint64_t cur_tap_rx = m_tap_rx_total;
        uint64_t cur_proxy_tx = m_proxy_tx_total;
        uint64_t cur_proxy_rx = m_proxy_rx_total;
        uint64_t cur_direct_tx = m_direct_tx_total;
        uint64_t cur_direct_rx = m_direct_rx_total;
        
        m_tap_tx_speed = cur_tap_tx - last_tap_tx;
        m_tap_rx_speed = cur_tap_rx - last_tap_rx;
        m_proxy_tx_speed = cur_proxy_tx - last_proxy_tx;
        m_proxy_rx_speed = cur_proxy_rx - last_proxy_rx;
        m_direct_tx_speed = cur_direct_tx - last_direct_tx;
        m_direct_rx_speed = cur_direct_rx - last_direct_rx;
        
        last_tap_tx = cur_tap_tx;
        last_tap_rx = cur_tap_rx;
        last_proxy_tx = cur_proxy_tx;
        last_proxy_rx = cur_proxy_rx;
        last_direct_tx = cur_direct_tx;
        last_direct_rx = cur_direct_rx;
    }
}

std::string TrafficManager::get_json_stats() {
    std::stringstream ss;
    ss << "{"
       << "\"tap\":{\"tx\":" << m_tap_tx_total << ",\"rx\":" << m_tap_rx_total
       << ",\"tx_speed\":" << m_tap_tx_speed << ",\"rx_speed\":" << m_tap_rx_speed << "},"
       << "\"proxy\":{"
       << "\"tx\":" << (m_proxy_tx_total + m_direct_tx_total) 
       << ",\"rx\":" << (m_proxy_rx_total + m_direct_rx_total)
       << ",\"proxy_tx_speed\":" << m_proxy_tx_speed 
       << ",\"proxy_rx_speed\":" << m_proxy_rx_speed 
       << ",\"direct_tx_speed\":" << m_direct_tx_speed 
       << ",\"direct_rx_speed\":" << m_direct_rx_speed 
       << "}"
       << "}";
    return ss.str();
}
