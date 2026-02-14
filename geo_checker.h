#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstdint>
#include <regex>
#include <set>
#include <atomic>
#include <thread>
#include <shared_mutex>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

// 注意：需要包含由 protoc 生成的头文件
#include "common.pb.h"

struct GeoIPRange {
    uint32_t start_ip;
    uint32_t end_ip;
    uint16_t code_index;

    // 排序仅基于 start_ip
    bool operator<(const GeoIPRange& other) const {
        return start_ip < other.start_ip;
    }
};

class GeoChecker {
public:
    static GeoChecker& instance();
    GeoChecker(); 
    ~GeoChecker();

    // Sync Init
    void init(const std::string& geoip_file = "geoip.dat", const std::string& geosite_file = "geosite.dat");
    bool is_ready() const { return m_ready; }

    // --------- IP 查询 ----------
    std::string query_ip(const std::string& ip_bytes);
    bool is_cn_ip(const uint32_t ip_host);

    // --------- 域名查询 ----------
    std::string query_domain(const std::string& domain);
    
    bool is_cn_domain(const std::string& domain);
    bool is_google_domain(const std::string& domain);
    bool is_tencent_domain(const std::string& domain);

    static bool is_private_ip(const uint32_t ip_host);

private:
    void load_data(const std::string& geoip_file, const std::string& geosite_file);
    void load_geoip(const std::string& filepath);
    void load_geosite(const std::string& filepath);
    
    uint16_t get_or_create_geoip_code(const std::string& code);
    uint16_t get_or_create_geosite_code(const std::string& code);

    // Sync
    std::atomic<bool> m_ready;
    mutable std::shared_mutex m_mtx;

    // 数据存储
    std::vector<std::string> geoip_codes_;
    std::vector<std::string> geosite_codes_;
    std::unordered_map<std::string, uint16_t> geoip_code_cache_;
    std::unordered_map<std::string, uint16_t> geosite_code_cache_;
    std::vector<GeoIPRange> ip_ranges_;

    // 使用 uint32_t 存储：低 16 位为 code_index，高 16 位为标志位 (1:CN, 2:GOOGLE, 4:TENCENT)
    std::unordered_map<std::string, uint32_t> domain_exact_;
    std::unordered_map<std::string, uint32_t> domain_suffix_;
    
    struct KeywordEntry {
        std::string keyword;
        uint16_t code_index;
        uint16_t flags;
    };
    std::vector<KeywordEntry> domain_keyword_;

    struct RegexEntry {
        std::regex reg;
        uint16_t code_index;
        uint16_t flags;
    };
    std::vector<RegexEntry> domain_regex_;

    std::set<uint16_t> cn_site_idxs_;
    std::set<uint16_t> google_site_idxs_;
    std::set<uint16_t> tencent_site_idxs_;
    
    uint16_t cn_ip_idx_ = 0xFFFF;

    static const uint32_t FLAG_CN = 0x10000;
    static const uint32_t FLAG_GOOGLE = 0x20000;
    static const uint32_t FLAG_TENCENT = 0x40000;
};