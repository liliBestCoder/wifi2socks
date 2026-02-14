#define NOMINMAX
#include "geo_checker.h"
#include "logger.h"
#include "app_config.h"
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <mutex>

// 辅助函数：转小写
static std::string to_lower(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), 
                   [](unsigned char c){ return std::tolower(c); });
    return lower;
}

// 辅助函数：转大写
static std::string to_upper(const std::string& str) {
    std::string upper = str;
    std::transform(upper.begin(), upper.end(), upper.begin(), 
                   [](unsigned char c){ return std::toupper(c); });
    return upper;
}

GeoChecker& GeoChecker::instance() {
    static GeoChecker inst;
    return inst;
}

GeoChecker::GeoChecker() : m_ready(false) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;
}

GeoChecker::~GeoChecker() {
}

void GeoChecker::load_data(const std::string& geoip_file, const std::string& geosite_file) {
    std::unique_lock<std::shared_mutex> lock(m_mtx);
    
    ip_ranges_.clear();
    domain_exact_.clear();
    domain_suffix_.clear();
    domain_keyword_.clear();
    domain_regex_.clear();
    
    load_geoip(geoip_file);
    load_geosite(geosite_file);

    geoip_code_cache_.clear();
    geosite_code_cache_.clear();

    m_ready = true;
}

void GeoChecker::init(const std::string& geoip_file, const std::string& geosite_file) {
    load_data(geoip_file, geosite_file);
    LOG_INFO("[Geo] Data initialized. IP ranges: %zu, Exact domains: %zu, Suffix domains: %zu", 
        ip_ranges_.size(), domain_exact_.size(), domain_suffix_.size());
}

static bool read_file_to_buffer(const std::string& filepath, std::vector<char>& buffer) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        LOG_ERROR("[Geo] Failed to open file: %s", filepath.c_str());
        return false;
    }
    std::streamsize size = file.tellg();
    if (size <= 0) return false;
    file.seekg(0, std::ios::beg);
    buffer.resize(size);
    if (file.read(buffer.data(), size)) return true;
    return false;
}

void GeoChecker::load_geoip(const std::string& filepath) {
    v2ray::core::app::router::routercommon::GeoIPList list;
    std::vector<char> buffer;
    if (!read_file_to_buffer(filepath, buffer)) return;
    if (!list.ParseFromArray(buffer.data(), (int)buffer.size())) {
        LOG_ERROR("[Geo] Failed to parse GeoIP protobuf from %s", filepath.c_str());
        return;
    }

    for (int i = 0; i < list.entry_size(); ++i) {
        const auto& entry = list.entry(i);
        uint16_t idx = get_or_create_geoip_code(entry.country_code());
        for (int j = 0; j < entry.cidr_size(); ++j) {
            const auto& cidr = entry.cidr(j);
            if (cidr.ip().size() != 4) continue; 
            uint32_t net_num = 0;
            memcpy(&net_num, cidr.ip().data(), 4);
            net_num = ntohl(net_num);
            uint32_t prefix = cidr.prefix();
            if (prefix > 32) prefix = 32; 
            uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
            if (prefix == 32) mask = 0xFFFFFFFFu;
            GeoIPRange range;
            range.start_ip = net_num & mask;
            range.end_ip = net_num | (~mask);
            range.code_index = idx;
            ip_ranges_.push_back(range);
        }
    }
    std::sort(ip_ranges_.begin(), ip_ranges_.end());
    LOG_INFO("[Geo] Loaded %d GeoIP entries", list.entry_size());
}

uint16_t GeoChecker::get_or_create_geoip_code(const std::string& code) {
    std::string upper_code = to_upper(code);
    auto it = geoip_code_cache_.find(upper_code);
    if (it != geoip_code_cache_.end()) return it->second;
    uint16_t idx = (uint16_t)geoip_codes_.size();
    geoip_codes_.push_back(upper_code);
    geoip_code_cache_[upper_code] = idx;
    if (upper_code == "CN") cn_ip_idx_ = idx;
    return idx;
}

uint16_t GeoChecker::get_or_create_geosite_code(const std::string& code) {
    std::string upper_code = to_upper(code);
    auto it = geosite_code_cache_.find(upper_code);
    if (it != geosite_code_cache_.end()) return it->second;
    uint16_t idx = (uint16_t)geosite_codes_.size();
    geosite_codes_.push_back(upper_code);
    geosite_code_cache_[upper_code] = idx;
    
    static const std::unordered_set<std::string> CN_TAGS = {
        "TENCENT", "QQ", "WECHAT", "ALIBABA", "TAOBAO", "ALIYUN", "TMALL", "DINGTALK",
        "BAIDU", "NETEASE", "163", "JD", "360", "SINA", "SOHU", "BILIBILI", "DOUYIN", 
        "HUAWEI", "XIAOMI", "OPPO", "VIVO", "MEITUAN"
    };

    bool is_cn = (upper_code.find("CN") != std::string::npos && upper_code.find("!CN") == std::string::npos) || CN_TAGS.count(upper_code);
    if (is_cn) cn_site_idxs_.insert(idx);
    if (upper_code.find("GOOGLE") != std::string::npos) google_site_idxs_.insert(idx);
    if (upper_code.find("TENCENT") != std::string::npos || upper_code.find("QQ") != std::string::npos || upper_code.find("WECHAT") != std::string::npos) tencent_site_idxs_.insert(idx);
    return idx;
}

void GeoChecker::load_geosite(const std::string& filepath) {
    v2ray::core::app::router::routercommon::GeoSiteList list;
    std::vector<char> buffer;
    if (!read_file_to_buffer(filepath, buffer)) return;
    if (!list.ParseFromArray(buffer.data(), (int)buffer.size())) {
        LOG_ERROR("[Geo] Failed to parse GeoSite protobuf from %s", filepath.c_str());
        return;
    }

    for (int i = 0; i < list.entry_size(); ++i) {
        const auto& entry = list.entry(i);
        uint16_t idx = get_or_create_geosite_code(entry.country_code());
        uint32_t flags = 0;
        if (cn_site_idxs_.count(idx)) flags |= FLAG_CN;
        if (google_site_idxs_.count(idx)) flags |= FLAG_GOOGLE;
        if (tencent_site_idxs_.count(idx)) flags |= FLAG_TENCENT;

        for (int j = 0; j < entry.domain_size(); ++j) {
            const auto& d = entry.domain(j);
            std::string val = d.value();
            int type = d.type();
            if (type != 1) val = to_lower(val); 
            
            switch (type) {
                case 3: // Exact
                    domain_exact_[val] = (domain_exact_[val] & 0xFFFF0000) | idx | flags;
                    domain_exact_[val] |= flags;
                    break;
                case 2: // Suffix
                case 4: // Subdomain
                    domain_suffix_[val] = (domain_suffix_[val] & 0xFFFF0000) | idx | flags;
                    domain_suffix_[val] |= flags;
                    break;
                case 0: // Keyword
                    domain_keyword_.push_back({val, idx, (uint16_t)(flags >> 16)});
                    break;
                case 1: // Regex
                    try { domain_regex_.push_back({std::regex(val, std::regex::icase | std::regex::optimize), idx, (uint16_t)(flags >> 16)}); } catch (...) {}
                    break;
                default:
                    domain_suffix_[val] = (domain_suffix_[val] & 0xFFFF0000) | idx | flags;
                    domain_suffix_[val] |= flags;
                    break;
            }
        }
    }
    LOG_INFO("[Geo] Loaded %d GeoSite entries", list.entry_size());
}

std::string GeoChecker::query_ip(const std::string& ip_bytes) {
    if (!m_ready || ip_bytes.size() != 4) return "UNKNOWN";
    uint32_t ip_num = 0;
    memcpy(&ip_num, ip_bytes.data(), 4);
    ip_num = ntohl(ip_num);
    
    std::shared_lock<std::shared_mutex> lock(m_mtx);
    auto it = std::upper_bound(ip_ranges_.begin(), ip_ranges_.end(), ip_num, [](uint32_t val, const GeoIPRange& range) { return val < range.start_ip; });
    if (it != ip_ranges_.begin()) {
        auto candidate = std::prev(it);
        if (ip_num >= candidate->start_ip && ip_num <= candidate->end_ip) return geoip_codes_[candidate->code_index];
    }
    return "UNKNOWN";
}

bool is_common_cn_range(uint32_t ip) {
    uint8_t first = (uint8_t)(ip >> 24);
    return (first == 112 || first == 223 || first == 36 || first == 180 || first == 183);
}

bool GeoChecker::is_private_ip(const uint32_t ip_h) {
    uint8_t b1 = (uint8_t)(ip_h >> 24);
    uint8_t b2 = (uint8_t)(ip_h >> 16);
    if (b1 == 10) return true; // 10.0.0.0/8
    if (b1 == 172 && (b2 >= 16 && b2 <= 31)) return true; // 172.16.0.0/12
    if (b1 == 192 && b2 == 168) return true; // 192.168.0.0/16
    if (b1 == 127) return true; // 127.0.0.0/8
    if (b1 == 169 && b2 == 254) return true; // 169.254.0.0/16
    return false;
}

bool GeoChecker::is_cn_ip(uint32_t ip_host) {
    if (is_private_ip(ip_host)) return true;
    if (!m_ready || cn_ip_idx_ == 0xFFFF) return false;
    std::shared_lock<std::shared_mutex> lock(m_mtx);
    auto it = std::lower_bound(ip_ranges_.begin(), ip_ranges_.end(), ip_host, [](const GeoIPRange& r, uint32_t val) { return r.end_ip < val; });
    if (it == ip_ranges_.end() || ip_host < it->start_ip || ip_host > it->end_ip) return is_common_cn_range(ip_host);
    return it->code_index == cn_ip_idx_;
}

std::string GeoChecker::query_domain(const std::string& domain) {
    if (!m_ready) return "UNKNOWN";
    std::string d = to_lower(domain);
    if (!d.empty() && d.back() == '.') d.pop_back();
    
    std::shared_lock<std::shared_mutex> lock(m_mtx);
    auto it_exact = domain_exact_.find(d);
    if (it_exact != domain_exact_.end()) return geosite_codes_[it_exact->second & 0xFFFF];

    size_t pos = 0;
    while (true) {
        std::string suffix = d.substr(pos);
        auto it_suffix = domain_suffix_.find(suffix);
        if (it_suffix != domain_suffix_.end()) return geosite_codes_[it_suffix->second & 0xFFFF];
        size_t next_dot = d.find('.', pos);
        if (next_dot == std::string::npos) break;
        pos = next_dot + 1;
    }
    for (const auto& kv : domain_keyword_) if (d.find(kv.keyword) != std::string::npos) return geosite_codes_[kv.code_index];
    for (const auto& kv : domain_regex_) if (std::regex_search(d, kv.reg)) return geosite_codes_[kv.code_index];
    return "UNKNOWN";
}

bool GeoChecker::is_cn_domain(const std::string& domain) {
    if (!m_ready) return false;
    std::string d = to_lower(domain);
    if (!d.empty() && d.back() == '.') d.pop_back();
    
    std::shared_lock<std::shared_mutex> lock(m_mtx);
    auto it_exact = domain_exact_.find(d);
    if (it_exact != domain_exact_.end() && (it_exact->second & FLAG_CN)) return true;

    size_t pos = 0;
    while (true) {
        std::string s = d.substr(pos);
        auto it = domain_suffix_.find(s);
        if (it != domain_suffix_.end() && (it->second & FLAG_CN)) return true;
        size_t next_dot = d.find('.', pos);
        if (next_dot == std::string::npos) break;
        pos = next_dot + 1;
    }
    for (const auto& kv : domain_keyword_) if ((kv.flags & (FLAG_CN >> 16)) && d.find(kv.keyword) != std::string::npos) return true;
    for (const auto& kv : domain_regex_) if ((kv.flags & (FLAG_CN >> 16)) && std::regex_search(d, kv.reg)) return true;
    
    if (d.length() > 3 && d.substr(d.length() - 3) == ".cn") return true;

    return false;
}

bool GeoChecker::is_google_domain(const std::string& domain) {
    if (!m_ready) return false;
    std::string d = to_lower(domain);
    if (!d.empty() && d.back() == '.') d.pop_back();

    std::shared_lock<std::shared_mutex> lock(m_mtx);
    auto it_exact = domain_exact_.find(d);
    if (it_exact != domain_exact_.end() && (it_exact->second & FLAG_GOOGLE)) return true;

    size_t pos = 0;
    while (true) {
        std::string s = d.substr(pos);
        auto it = domain_suffix_.find(s);
        if (it != domain_suffix_.end() && (it->second & FLAG_GOOGLE)) return true;
        size_t next_dot = d.find('.', pos);
        if (next_dot == std::string::npos) break;
        pos = next_dot + 1;
    }
    return false;
}

bool GeoChecker::is_tencent_domain(const std::string& domain) {
    if (!m_ready) return false;
    std::string d = to_lower(domain);
    if (!d.empty() && d.back() == '.') d.pop_back();

    std::shared_lock<std::shared_mutex> lock(m_mtx);
    auto it_exact = domain_exact_.find(d);
    if (it_exact != domain_exact_.end() && (it_exact->second & FLAG_TENCENT)) return true;

    size_t pos = 0;
    while (true) {
        std::string s = d.substr(pos);
        auto it = domain_suffix_.find(s);
        if (it != domain_suffix_.end() && (it->second & FLAG_TENCENT)) return true;
        size_t next_dot = d.find('.', pos);
        if (next_dot == std::string::npos) break;
        pos = next_dot + 1;
    }
    return false;
}
