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
    GeoChecker(const std::string& geoip_file = "geoip.dat", const std::string& geosite_file = "geosite.dat");
    ~GeoChecker();

    // --------- IP 查询 ----------
    // ip_bytes 应当为 4 字节的二进制字符串（网络字节序）
    std::string query_ip(const std::string& ip_bytes);
    bool is_cn_ip(const std::string& ip_bytes);

    // --------- 域名查询 ----------
    std::string query_domain(const std::string& domain);
    
    // 专用判定函数（高性能优化版）
    bool is_cn_domain(const std::string& domain);
    bool is_google_domain(const std::string& domain);
    bool is_tencent_domain(const std::string& domain);

private:
    void load_geoip(const std::string& filepath);
    void load_geosite(const std::string& filepath);
    
    uint16_t get_or_create_geoip_code(const std::string& code);
    uint16_t get_or_create_geosite_code(const std::string& code);

    // 数据存储 - 分离 GeoIP 和 GeoSite
    std::vector<std::string> geoip_codes_;
    std::vector<std::string> geosite_codes_;

    // 加载时的临时索引 Cache (O(1) 查找)
    std::unordered_map<std::string, uint16_t> geoip_code_cache_;
    std::unordered_map<std::string, uint16_t> geosite_code_cache_;

    // IP 数据
    std::vector<GeoIPRange> ip_ranges_;

    // 域名匹配规则
    // 1. Full/Exact: 完整匹配
    std::unordered_map<std::string, uint16_t> domain_exact_;
    // 2. Domain/Suffix: 后缀匹配 (存储为 subdomain.google.com -> code)
    std::unordered_map<std::string, uint16_t> domain_suffix_;
    // 3. Plain/Keyword: 关键字包含 (存储 <keyword, code>)
    std::vector<std::pair<std::string, uint16_t>> domain_keyword_;
    // 4. Regex: 正则匹配 (存储 <regex, code>)
    std::vector<std::pair<std::regex, uint16_t>> domain_regex_;

    // 预计算的关键 Tag 索引 (加速 is_cn_domain 等)
    // 使用 set 存储，因为 "cn" 可能对应 "CN" 和 "cn" (如果不规范) 
    // 或者 geosite 可能有多个类别都算 CN (如 "geolocation-cn")
    std::set<uint16_t> cn_site_idxs_;
    std::set<uint16_t> google_site_idxs_;
    std::set<uint16_t> tencent_site_idxs_;
    
    uint16_t cn_ip_idx_ = 0xFFFF;
};