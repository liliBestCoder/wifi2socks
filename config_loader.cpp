#include "config_loader.h"
#include "app_config.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <vector>

AppConfig g_config;

static std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (std::string::npos == first) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

static std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) {
        std::string trimmed = trim(token);
        if (!trimmed.empty()) {
            tokens.push_back(trimmed);
        }
    }
    return tokens;
}

bool load_config(const char* filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Config file " << filepath << " not found. Using defaults.\n";
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line[0] == '[') continue; // Skip sections for now, simple key-value

        size_t delimiterPos = line.find('=');
        if (delimiterPos == std::string::npos) continue;
        
        std::string key = trim(line.substr(0, delimiterPos));
        std::string value = trim(line.substr(delimiterPos + 1));
        
        try {
            if (key == "tap_ip") g_config.tap_ip = value;
            else if (key == "tap_netmask") g_config.tap_netmask = value;
            else if (key == "tap_gateway") g_config.tap_gateway = value;
            else if (key == "tap_mac") g_config.tap_mac = value;
            else if (key == "proxy_ip") g_config.proxy_ip = value;
            else if (key == "proxy_port") g_config.proxy_port = (uint16_t)std::stoi(value);
            else if (key == "lwip_listen_port") g_config.lwip_listen_port = (uint16_t)std::stoi(value);
            else if (key == "max_sni_len") g_config.max_sni_len = (uint32_t)std::stoul(value);
            else if (key == "http_api_port") g_config.http_api_port = (uint16_t)std::stoi(value);
            else if (key == "wifi_ssid") g_config.wifi_ssid = value;
            else if (key == "wifi_password") g_config.wifi_password = value;
            else if (key == "direct_ip_list") g_config.direct_ip_list = split(value, ',');
            else if (key == "direct_domain_list") g_config.direct_domain_list = split(value, ',');
            else if (key == "block_ip_list") g_config.block_ip_list = split(value, ',');
            else if (key == "block_domain_list") g_config.block_domain_list = split(value, ',');
            else if (key == "proxy_ip_list") g_config.proxy_ip_list = split(value, ',');
            else if (key == "proxy_domain_list") g_config.proxy_domain_list = split(value, ',');
        } catch (...) {
            std::cerr << "Error parsing config key: " << key << "\n";
        }
    }

    return true;
}

static std::string join(const std::vector<std::string>& vec, char delimiter) {
    std::stringstream ss;
    for (size_t i = 0; i < vec.size(); ++i) {
        ss << vec[i];
        if (i != vec.size() - 1) {
            ss << delimiter << " ";
        }
    }
    return ss.str();
}

bool save_config(const char* filepath) {
    std::ofstream file(filepath);
    if (!file.is_open()) return false;

    file << "[Common]\n";
    file << "tap_ip = " << g_config.tap_ip << "\n";
    file << "tap_netmask = " << g_config.tap_netmask << "\n";
    file << "tap_gateway = " << g_config.tap_gateway << "\n";
    file << "tap_mac = " << g_config.tap_mac << "\n\n";

    file << "proxy_ip = " << g_config.proxy_ip << "\n";
    file << "proxy_port = " << g_config.proxy_port << "\n\n";

    file << "lwip_listen_port = " << g_config.lwip_listen_port << "\n";
    file << "max_sni_len = " << g_config.max_sni_len << "\n";
    file << "http_api_port = " << g_config.http_api_port << "\n";
    file << "wifi_ssid = " << g_config.wifi_ssid << "\n";
    file << "wifi_password = " << g_config.wifi_password << "\n\n";

    file << "[Rules]\n";
    file << "direct_ip_list = " << join(g_config.direct_ip_list, ',') << "\n";
    file << "direct_domain_list = " << join(g_config.direct_domain_list, ',') << "\n";
    file << "block_ip_list = " << join(g_config.block_ip_list, ',') << "\n";
    file << "block_domain_list = " << join(g_config.block_domain_list, ',') << "\n";
    file << "proxy_ip_list = " << join(g_config.proxy_ip_list, ',') << "\n";
    file << "proxy_domain_list = " << join(g_config.proxy_domain_list, ',') << "\n";

    return true;
}
