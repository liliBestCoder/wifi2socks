#include "geo_checker.h"
#include <stdexcept>

GeoChecker& GeoChecker::instance() {
    static GeoChecker inst;
    return inst;
}

GeoChecker::GeoChecker(const std::string& geoip_file, const std::string& geosite_file) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    load_geoip(geoip_file);
    load_geosite(geosite_file);
}

GeoChecker::~GeoChecker() {
    // 注意：在多线程环境下，ShutdownProtobufLibrary 应该在整个程序退出时调用
    // 这里为了局部完整性保留，但需注意全局影响
    // google::protobuf::ShutdownProtobufLibrary();
}

uint16_t GeoChecker::get_or_create_country_index(const std::string& code) {
    for (size_t i = 0; i < country_codes_.size(); ++i) {
        if (country_codes_[i] == code) return static_cast<uint16_t>(i);
    }
    country_codes_.push_back(code);
    return static_cast<uint16_t>(country_codes_.size() - 1);
}

void GeoChecker::load_geoip(const std::string& filepath) {
    v2ray::core::app::router::routercommon::GeoIPList list;
    std::ifstream fin(filepath, std::ios::binary);
    if (!fin.is_open()) throw std::runtime_error("Failed to open " + filepath);
    if (!list.ParseFromIstream(&fin)) throw std::runtime_error("Failed to parse " + filepath);

    for (int i = 0; i < list.entry_size(); ++i) {
        const auto& entry = list.entry(i);
        uint16_t idx = get_or_create_country_index(entry.country_code());
        
        for (int j = 0; j < entry.cidr_size(); ++j) {
            const auto& cidr = entry.cidr(j);
            if (cidr.ip().size() != 4) continue; // 暂仅支持 IPv4

            uint32_t net_num = ntohl(*reinterpret_cast<const uint32_t*>(cidr.ip().data()));
            uint32_t mask = (cidr.prefix() == 0) ? 0 : (0xFFFFFFFF << (32 - cidr.prefix()));
            
            IPRange range;
            range.start_ip = net_num & mask;
            range.end_ip = net_num | (~mask);
            range.country_index = idx;
            ip_list_v4_.push_back(range);
        }
    }

    // 排序以便二分查找
    std::sort(ip_list_v4_.begin(), ip_list_v4_.end(), [](const IPRange& a, const IPRange& b) {
        return a.start_ip < b.start_ip;
    });
}

void GeoChecker::load_geosite(const std::string& filepath) {
    v2ray::core::app::router::routercommon::GeoSiteList list;
    std::ifstream fin(filepath, std::ios::binary);
    if (!fin.is_open()) throw std::runtime_error("Failed to open " + filepath);
    if (!list.ParseFromIstream(&fin)) throw std::runtime_error("Failed to parse " + filepath);

    for (int i = 0; i < list.entry_size(); ++i) {
        const auto& entry = list.entry(i);
        uint16_t idx = get_or_create_country_index(entry.country_code());

        for (int j = 0; j < entry.domain_size(); ++j) {
            const auto& d = entry.domain(j);
            // v2ray domain type: 0=Plain, 1=Regex, 2=RootDomain, 3=Full
            if (d.type() == 3) { // Full
                full_domain_map_[d.value()] = idx;
            } else if (d.type() == 2 || d.type() == 0) { // RootDomain or Plain (treated as suffix)
                root_domain_map_[d.value()] = idx;
            }
        }
    }
}

std::string GeoChecker::query_ip(const std::string& ip_bytes) {
    if (ip_bytes.size() != 4) return "UNKNOWN";
    uint32_t ip_num = ntohl(*reinterpret_cast<const uint32_t*>(ip_bytes.data()));

    // 二分查找
    auto it = std::lower_bound(ip_list_v4_.begin(), ip_list_v4_.end(), ip_num, 
        [](const IPRange& range, uint32_t val) {
            return range.end_ip < val;
        });

    if (it != ip_list_v4_.end() && ip_num >= it->start_ip && ip_num <= it->end_ip) {
        return country_codes_[it->country_index];
    }
    return "UNKNOWN";
}

bool GeoChecker::is_cn_ip(const std::string& ip_bytes) {
    return query_ip(ip_bytes) == "CN";
}

std::string GeoChecker::query_domain(const std::string& domain) {
    // 1. 全域名匹配
    auto it = full_domain_map_.find(domain);
    if (it != full_domain_map_.end()) return country_codes_[it->second];

    // 2. 后缀/子域名匹配
    std::string sub = domain;
    while (!sub.empty()) {
        auto it_root = root_domain_map_.find(sub);
        if (it_root != root_domain_map_.end()) return country_codes_[it_root->second];

        size_t dot_pos = sub.find('.');
        if (dot_pos == std::string::npos) break;
        sub = sub.substr(dot_pos + 1);
    }

    return "UNKNOWN";
}

bool GeoChecker::is_cn_domain(const std::string& domain) {
    return query_domain(domain) == "CN";
}

bool GeoChecker::is_google_domain(const std::string& domain) {
    std::string code = query_domain(domain);
    return code == "GOOGLE" || domain.find("google") != std::string::npos;
}

bool GeoChecker::is_tencent_domain(const std::string& domain) {
    std::string code = query_domain(domain);
    return code == "TENCENT" || domain.find("qq") != std::string::npos || domain.find("wechat") != std::string::npos;
}
