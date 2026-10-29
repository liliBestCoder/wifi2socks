#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <cstdint>

enum class RouteAction {
    PASS = 0, // No match, proceed to GeoIP
    DIRECT,
    BLOCK,
    PROXY
};

class RuleManager {
public:
    static RuleManager& instance();

    // Initialize/Reload from global config
    void reload();

    // Query
    RouteAction match_ip(uint32_t ip);
    RouteAction match_domain(const std::string& domain);

    // Updates (Updates global config and saves to file)
    void update_direct_list(const std::vector<std::string>& ips, const std::vector<std::string>& domains);
    void update_block_list(const std::vector<std::string>& ips, const std::vector<std::string>& domains);
    void update_proxy_list(const std::vector<std::string>& ips, const std::vector<std::string>& domains);

private:
    RuleManager();
    
    struct Cidr {
        uint32_t ip;
        uint32_t mask;
    };

    void parse_cidr_list(const std::vector<std::string>& list, std::vector<Cidr>& out);
    void parse_domain_list(const std::vector<std::string>& list, std::unordered_set<std::string>& out);
    bool cidr_match(uint32_t ip, const std::vector<Cidr>& cidrs);

    std::mutex m_mtx;
    
    // Parsed Rules
    std::vector<Cidr> m_direct_cidrs;
    std::vector<Cidr> m_block_cidrs;
    std::vector<Cidr> m_proxy_cidrs;

    std::unordered_set<std::string> m_direct_domains;
    std::unordered_set<std::string> m_block_domains;
    std::unordered_set<std::string> m_proxy_domains;
};
