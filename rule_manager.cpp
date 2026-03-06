#include "rule_manager.h"
#include "app_config.h"
#include "config_loader.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

RuleManager& RuleManager::instance() {
    static RuleManager inst;
    return inst;
}

RuleManager::RuleManager() {
    reload();
}

static uint32_t parse_ip(const std::string& ip_str) {
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip_str.c_str(), &(sa.sin_addr)) == 1) {
        return ntohl(sa.sin_addr.s_addr);
    }
    return 0;
}

void RuleManager::parse_cidr_list(const std::vector<std::string>& list, std::vector<Cidr>& out) {
    out.clear();
    for (const auto& item : list) {
        if (item.empty()) continue;
        size_t slash = item.find('/');
        std::string ip_part = item;
        int prefix = 32;
        
        if (slash != std::string::npos) {
            ip_part = item.substr(0, slash);
            try {
                prefix = std::stoi(item.substr(slash + 1));
            } catch (...) { prefix = 32; }
        }
        
        if (prefix < 0) prefix = 0;
        if (prefix > 32) prefix = 32;
        
        uint32_t ip = parse_ip(ip_part);
        if (ip == 0 && ip_part != "0.0.0.0") continue; // Invalid IP
        
        uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
        out.push_back({ip & mask, mask});
    }
}

void RuleManager::parse_domain_list(const std::vector<std::string>& list, std::unordered_set<std::string>& out) {
    out.clear();
    for (const auto& item : list) {
        if (item.empty()) continue;
        std::string d = item;
        // Basic normalization: lower case
        std::transform(d.begin(), d.end(), d.begin(), ::tolower);
        out.insert(d);
    }
}

void RuleManager::reload() {
    std::lock_guard<std::mutex> lock(m_mtx);
    parse_cidr_list(g_config.direct_ip_list, m_direct_cidrs);
    parse_domain_list(g_config.direct_domain_list, m_direct_domains);
    
    parse_cidr_list(g_config.block_ip_list, m_block_cidrs);
    parse_domain_list(g_config.block_domain_list, m_block_domains);
    
    parse_cidr_list(g_config.proxy_ip_list, m_proxy_cidrs);
    parse_domain_list(g_config.proxy_domain_list, m_proxy_domains);
}

bool RuleManager::cidr_match(uint32_t ip, const std::vector<Cidr>& cidrs) {
    for (const auto& cidr : cidrs) {
        if ((ip & cidr.mask) == cidr.ip) return true;
    }
    return false;
}

// Domain match: suffix match
static bool domain_match_set(const std::string& domain, const std::unordered_set<std::string>& set) {
    if (set.empty()) return false;
    std::string d = domain;
    std::transform(d.begin(), d.end(), d.begin(), ::tolower);
    if (!d.empty() && d.back() == '.') d.pop_back();

    // Check exact match first
    if (set.count(d)) return true;

    // Check suffix
    size_t pos = 0;
    while ((pos = d.find('.', pos)) != std::string::npos) {
        std::string suffix = d.substr(pos + 1); // skip dot
        if (set.count(suffix)) return true;
        pos++;
    }
    return false;
}

RouteAction RuleManager::match_ip(uint32_t ip) {
    // Priority: Block > Direct > Proxy
    // Why? Security/Blocklist usually comes first.
    // Direct/Proxy order depends on user intent, usually explicit Direct overrides Proxy.
    
    /*std::lock_guard<std::mutex> lock(m_mtx);
    if (cidr_match(ip, m_block_cidrs)) return RouteAction::BLOCK;
    if (cidr_match(ip, m_direct_cidrs)) return RouteAction::DIRECT;
    if (cidr_match(ip, m_proxy_cidrs)) return RouteAction::PROXY;
    
    return RouteAction::PASS;*/

    return RouteAction::DIRECT;
}

RouteAction RuleManager::match_domain(const std::string& domain) {
    /*std::lock_guard<std::mutex> lock(m_mtx);
    if (domain_match_set(domain, m_block_domains)) return RouteAction::BLOCK;
    if (domain_match_set(domain, m_direct_domains)) return RouteAction::DIRECT;
    if (domain_match_set(domain, m_proxy_domains)) return RouteAction::PROXY;
    
    return RouteAction::PASS;*/

    return RouteAction::DIRECT;
}

void RuleManager::update_direct_list(const std::vector<std::string>& ips, const std::vector<std::string>& domains) {
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        g_config.direct_ip_list = ips;
        g_config.direct_domain_list = domains;
    }
    save_config("config.ini");
    reload();
}

void RuleManager::update_block_list(const std::vector<std::string>& ips, const std::vector<std::string>& domains) {
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        g_config.block_ip_list = ips;
        g_config.block_domain_list = domains;
    }
    save_config("config.ini");
    reload();
}

void RuleManager::update_proxy_list(const std::vector<std::string>& ips, const std::vector<std::string>& domains) {
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        g_config.proxy_ip_list = ips;
        g_config.proxy_domain_list = domains;
    }
    save_config("config.ini");
    reload();
}
