#include "geo_checker.h"
#include <stdexcept>
#include <algorithm>
#include <cctype>

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

GeoChecker::GeoChecker(const std::string& geoip_file, const std::string& geosite_file) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    load_geoip(geoip_file);
    load_geosite(geosite_file);
}

GeoChecker::~GeoChecker() {
    // google::protobuf::ShutdownProtobufLibrary();
}

uint16_t GeoChecker::get_or_create_geoip_code(const std::string& code) {
    std::string upper_code = to_upper(code);
    auto it = geoip_code_cache_.find(upper_code);
    if (it != geoip_code_cache_.end()) return it->second;

    uint16_t idx = (uint16_t)geoip_codes_.size();
    geoip_codes_.push_back(upper_code);
    geoip_code_cache_[upper_code] = idx;
    
    if (upper_code == "CN") {
        cn_ip_idx_ = idx;
    }
    return idx;
}

uint16_t GeoChecker::get_or_create_geosite_code(const std::string& code) {
    std::string upper_code = to_upper(code);
    auto it = geosite_code_cache_.find(upper_code);
    if (it != geosite_code_cache_.end()) return it->second;

    uint16_t idx = (uint16_t)geosite_codes_.size();
    geosite_codes_.push_back(upper_code);
    geosite_code_cache_[upper_code] = idx;

    // --- 1. 定义已知国内 Tag 列表 (白名单) ---
    // 使用 static set 避免重复构造，且查找快
    static const std::unordered_set<std::string> CN_TAGS = {
        // 核心互联网巨头
        "TENCENT", "QQ", "WECHAT", 
        "ALIBABA", "TAOBAO", "ALIYUN", "TMALL", "DINGTALK",
        "BAIDU", "NETEASE", "163", "JD", "360", "SINA", "SOHU",
        "BILIBILI", "DOUYIN", "UNKNOWN",
        "IQOO", 
        
        // 手机/硬件厂商 (用于云服务直连)
        "HUAWEI", "XIAOMI", "OPPO", "VIVO", "ONEPLUS", "ALLAWN", "MEIZU", "ZTE", "DJI",
        
        // 其他常见国内服务
        "CTRIP", "MEITUAN", "PINDUODUO", "KUAISHOU", "XHS", // 小红书
        "ELEVOC", "KINGSOFT", "IFLYTEK"
    };

    // --- 2. 判定是否为 CN ---
    bool is_cn = false;
    
    // 规则 A: 包含 "CN" 子串 (如 "CATEGORY-CN", "GEOLOCATION-CN")
    // 修正: 排除 "!CN" (如 "GEOLOCATION-!CN")
    if (upper_code.find("CN") != std::string::npos && upper_code.find("!CN") == std::string::npos) {
        is_cn = true;
    }
    // 规则 C: 命中白名单 (精确查找或子串包含)
    else {
        // 优先精确查找
        if (CN_TAGS.count(upper_code)) {
            is_cn = true;
        } else {
            // 遍历白名单检查是否包含 (例如 "CATEGORY-HUAWEI" 包含 "HUAWEI")
            // 虽然是 O(N)，但 N 较小且仅在加载时执行一次
            for (const auto& tag : CN_TAGS) {
                if (upper_code.find(tag) != std::string::npos) {
                    is_cn = true;
                    break;
                }
            }
        }
    }

    if (is_cn) cn_site_idxs_.insert(idx);

    // --- 3. 判定特定大厂 (用于更细粒度的逻辑) ---
    if (upper_code.find("GOOGLE") != std::string::npos) google_site_idxs_.insert(idx);
    
    bool is_tencent = false;
    if (upper_code.find("TENCENT") != std::string::npos) is_tencent = true;
    else if (upper_code.find("QQ") != std::string::npos) is_tencent = true;
    else if (upper_code.find("WECHAT") != std::string::npos) is_tencent = true;
    if (is_tencent) tencent_site_idxs_.insert(idx);

    return idx;
}

void GeoChecker::load_geoip(const std::string& filepath) {
    v2ray::core::app::router::routercommon::GeoIPList list;
    std::ifstream fin(filepath, std::ios::binary);
    // 如果文件不存在，仅打印错误不抛出，以免 crash
    if (!fin.is_open()) {
        std::cerr << "[GeoChecker] Failed to open " << filepath << std::endl;
        return;
    }
    if (!list.ParseFromIstream(&fin)) {
        std::cerr << "[GeoChecker] Failed to parse " << filepath << std::endl;
        return;
    }

    for (int i = 0; i < list.entry_size(); ++i) {
        const auto& entry = list.entry(i);
        uint16_t idx = get_or_create_geoip_code(entry.country_code());
        
        for (int j = 0; j < entry.cidr_size(); ++j) {
            const auto& cidr = entry.cidr(j);
            if (cidr.ip().size() != 4) continue; 

            uint32_t net_num = ntohl(*reinterpret_cast<const uint32_t*>(cidr.ip().data()));
            uint32_t prefix = cidr.prefix();
            if (prefix > 32) prefix = 32; // 安全防护

            // 修复 UB：当 prefix=0 时，32-0=32，0xFFFFFFFF << 32 是未定义行为
            uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
            
            GeoIPRange range;
            range.start_ip = net_num & mask;
            range.end_ip = net_num | (~mask);
            range.code_index = idx;
            ip_ranges_.push_back(range);
        }
    }

    // 排序
    std::sort(ip_ranges_.begin(), ip_ranges_.end());
}

void GeoChecker::load_geosite(const std::string& filepath) {
    v2ray::core::app::router::routercommon::GeoSiteList list;
    std::ifstream fin(filepath, std::ios::binary);
    if (!fin.is_open()) {
        std::cerr << "[GeoChecker] Failed to open " << filepath << std::endl;
        return;
    }
    if (!list.ParseFromIstream(&fin)) {
        std::cerr << "[GeoChecker] Failed to parse " << filepath << std::endl;
        return;
    }

    for (int i = 0; i < list.entry_size(); ++i) {
        const auto& entry = list.entry(i);
        uint16_t idx = get_or_create_geosite_code(entry.country_code());

        for (int j = 0; j < entry.domain_size(); ++j) {
            const auto& d = entry.domain(j);
            std::string val = d.value();
            int type = d.type();
            
            if (type != 1) { // 1 = Regex. 其他类型统一转小写
                 val = to_lower(val); 
            }

            switch (type) {
                case 3: // Full (Exact)
                    {
                        auto it = domain_exact_.find(val);
                        if (it != domain_exact_.end()) {
                            // 冲突：保护 Google Tag 不被覆盖
                            // 冲突解决：保护高优先级 Tag (Google, CN)
                            bool old_is_google = google_site_idxs_.count(it->second);
                            bool new_is_google = google_site_idxs_.count(idx);
                            bool old_is_cn = cn_site_idxs_.count(it->second);
                            bool new_is_cn = cn_site_idxs_.count(idx);

                            if (old_is_google && !new_is_google) break;
                            if (old_is_cn && !new_is_cn && !new_is_google) break; 
                        }
                        domain_exact_[val] = idx;
                    }
                    break;
                case 2: // Domain (Suffix)
                    {
                        auto it = domain_suffix_.find(val);
                        if (it != domain_suffix_.end()) {
                            // 冲突：保护 Google Tag 不被覆盖
                            // 冲突解决：保护高优先级 Tag (Google, CN)
                            bool old_is_google = google_site_idxs_.count(it->second);
                            bool new_is_google = google_site_idxs_.count(idx);
                            bool old_is_cn = cn_site_idxs_.count(it->second);
                            bool new_is_cn = cn_site_idxs_.count(idx);

                            if (old_is_google && !new_is_google) break;
                            if (old_is_cn && !new_is_cn && !new_is_google) break; 
                        }
                        domain_suffix_[val] = idx;
                    }
                    break;
                case 0: // Plain (Keyword/Substring)
                    domain_keyword_.push_back({val, idx});
                    break;
                case 1: // Regex
                    try {
                        domain_regex_.push_back({std::regex(val, std::regex::icase | std::regex::optimize), idx});
                    } catch (...) {
                        // 忽略错误的正则
                    }
                    break;
                default:
                    // 默认当作 Suffix
                    {
                        auto it = domain_suffix_.find(val);
                        if (it != domain_suffix_.end()) {
                            // 冲突解决：保护高优先级 Tag (Google, CN)
                            bool old_is_google = google_site_idxs_.count(it->second);
                            bool new_is_google = google_site_idxs_.count(idx);
                            bool old_is_cn = cn_site_idxs_.count(it->second);
                            bool new_is_cn = cn_site_idxs_.count(idx);

                            if (old_is_google && !new_is_google) break;
                            if (old_is_cn && !new_is_cn && !new_is_google) break; 
                        }
                        domain_suffix_[val] = idx;
                    }
                    break;
            }
        }
    }
}

std::string GeoChecker::query_ip(const std::string& ip_bytes) {
    if (ip_bytes.size() != 4) return "UNKNOWN";
    uint32_t ip_num = ntohl(*reinterpret_cast<const uint32_t*>(ip_bytes.data()));

    // upper_bound 找到第一个 start_ip > ip_num 的 range
    auto it = std::upper_bound(ip_ranges_.begin(), ip_ranges_.end(), ip_num, 
        [](uint32_t val, const GeoIPRange& range) {
            return val < range.start_ip;
        });

    // 检查前一个 range
    if (it != ip_ranges_.begin()) {
        auto candidate = std::prev(it);
        if (ip_num >= candidate->start_ip && ip_num <= candidate->end_ip) {
            return geoip_codes_[candidate->code_index];
        }
    }
    return "UNKNOWN";
}

bool GeoChecker::is_cn_ip(const std::string& ip_bytes) {
    if (ip_bytes.size() != 4 || cn_ip_idx_ == UINT16_MAX) return false;

    uint32_t ip = ntohl(*reinterpret_cast<const uint32_t*>(ip_bytes.data()));

    auto it = std::lower_bound(
        ip_ranges_.begin(),
        ip_ranges_.end(),
        ip,
        [](const GeoIPRange& r, uint32_t val) {
            return r.end_ip < val;
        }
    );

    if (it == ip_ranges_.end()) return false;

    return ip >= it->start_ip &&
        ip <= it->end_ip &&
        it->code_index == cn_ip_idx_;
}



std::string GeoChecker::query_domain(const std::string& domain) {
    std::string d = to_lower(domain);
    if (!d.empty() && d.back() == '.') d.pop_back(); // 去除结尾的点

    // 1. Exact
    auto it_exact = domain_exact_.find(d);
    if (it_exact != domain_exact_.end()) return geosite_codes_[it_exact->second];

    // 2. Suffix
    // 逻辑：不断去掉第一段，查找剩余部分
    size_t pos = 0;
    while (true) {
        // 检查 d.substr(pos) 是否在 map 中
        // 为了避免 alloc，理想情况需 C++20 透明查找。这里折中使用 substr
        std::string suffix = d.substr(pos);
        auto it = domain_suffix_.find(suffix);
        if (it != domain_suffix_.end()) return geosite_codes_[it->second];

        size_t next_dot = d.find('.', pos);
        if (next_dot == std::string::npos) break;
        pos = next_dot + 1;
    }

    // 3. Keyword (Plain) - 性能敏感，但 Geosite 中 Plain 规则通常不多
    for (const auto& kv : domain_keyword_) {
        if (d.find(kv.first) != std::string::npos) {
            return geosite_codes_[kv.second];
        }
    }

    // 4. Regex
    for (const auto& kv : domain_regex_) {
        if (std::regex_search(d, kv.first)) {
            return geosite_codes_[kv.second];
        }
    }

    return "UNKNOWN";
}

// 通用检查逻辑：是否存在于指定的索引集合中
bool is_in_set(const std::string& domain, 
              const std::unordered_map<std::string, uint16_t>& exact,
              const std::unordered_map<std::string, uint16_t>& suffix,
              const std::vector<std::pair<std::string, uint16_t>>& keyword,
              const std::vector<std::pair<std::regex, uint16_t>>& regex_rules,
              const std::set<uint16_t>& target_idxs) {
    
    std::string d = to_lower(domain);
    if (!d.empty() && d.back() == '.') d.pop_back();

    // 1. Exact
    auto it_exact = exact.find(d);
    if (it_exact != exact.end()) {
        return target_idxs.count(it_exact->second) > 0;
    }

    // 2. Suffix
    size_t pos = 0;
    while (true) {
        std::string s = d.substr(pos);
        auto it = suffix.find(s);
        if (it != suffix.end()) {
             return target_idxs.count(it->second) > 0;
        }
        size_t next_dot = d.find('.', pos);
        if (next_dot == std::string::npos) break;
        pos = next_dot + 1;
    }

    // 3. Keyword
    for (const auto& kv : keyword) {
        if (target_idxs.count(kv.second)) {
            if (d.find(kv.first) != std::string::npos) return true;
        }
    }

    // 4. Regex
    for (const auto& kv : regex_rules) {
        if (target_idxs.count(kv.second)) {
             if (std::regex_search(d, kv.first)) return true;
        }
    }

    return false;
}

bool GeoChecker::is_cn_domain(const std::string& domain) {
    return is_in_set(domain, domain_exact_, domain_suffix_, domain_keyword_, domain_regex_, cn_site_idxs_);
}

bool GeoChecker::is_google_domain(const std::string& domain) {
    return is_in_set(domain, domain_exact_, domain_suffix_, domain_keyword_, domain_regex_, google_site_idxs_);
}

bool GeoChecker::is_tencent_domain(const std::string& domain) {
    return is_in_set(domain, domain_exact_, domain_suffix_, domain_keyword_, domain_regex_, tencent_site_idxs_);
}
