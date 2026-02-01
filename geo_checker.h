#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

// 注意：需要包含由 protoc 生成的头文件
#include "routercommon.pb.h"

struct IPRange {
    uint32_t start_ip;
    uint32_t end_ip;
    uint16_t country_index; // 为了节省内存，使用索引指向国家代码字符串

    bool operator<(const IPRange& other) const {
        return end_ip < other.start_ip;
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
    bool is_cn_domain(const std::string& domain);
    bool is_google_domain(const std::string& domain);
    bool is_tencent_domain(const std::string& domain);

private:
    void load_geoip(const std::string& filepath);
    void load_geosite(const std::string& filepath);
    
    // 将域名反转（如 com.google）以便进行后缀匹配
    static std::string reverse_domain(const std::string& domain);

    std::vector<IPRange> ip_list_v4_;
    std::vector<std::string> country_codes_;
    
    // 域名匹配映射
    // key: 反转后的域名, value: 国家代码索引
    std::unordered_map<std::string, uint16_t> full_domain_map_;
    std::unordered_map<std::string, uint16_t> root_domain_map_;

    uint16_t get_or_create_country_index(const std::string& code);
};
