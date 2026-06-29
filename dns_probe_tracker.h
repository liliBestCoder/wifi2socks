#pragma once

#include <winsock2.h>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct DnsProbeHint {
    std::string domain;
    std::string probe_class;
    uint64_t expire_tick{ 0 };
};

class DnsProbeTracker {
public:
    static DnsProbeTracker& instance() {
        static DnsProbeTracker tracker;
        return tracker;
    }

    void put(uint32_t ip_nbo, const std::string& domain, uint32_t ttl_seconds) {
        std::string cls = classify(domain);
        if (ip_nbo == 0 || cls.empty()) return;

        uint32_t ttl = ttl_seconds;
        if (ttl < 60) ttl = 60;
        if (ttl > 600) ttl = 600;

        std::lock_guard<std::mutex> lock(m_mutex);
        cleanup_locked(GetTickCount64());
        m_hints[ip_nbo] = DnsProbeHint{ strip_host_port(domain), cls, GetTickCount64() + (uint64_t)ttl * 1000ULL };
    }

    void put_many(const std::vector<std::string>& addresses, const std::string& domain, uint32_t ttl_seconds) {
        for (const auto& ip_text : addresses) {
            uint32_t ip_nbo = 0;
            if (inet_pton(AF_INET, ip_text.c_str(), &ip_nbo) == 1) {
                put(ip_nbo, domain, ttl_seconds);
            }
        }
    }

    bool lookup(uint32_t ip_nbo, DnsProbeHint* out) {
        uint64_t now = GetTickCount64();
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_hints.find(ip_nbo);
        if (it == m_hints.end()) return false;
        if (it->second.expire_tick <= now) {
            m_hints.erase(it);
            return false;
        }
        if (out) *out = it->second;
        return true;
    }

private:
    static std::string lower_ascii(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        if (!s.empty() && s.back() == '.') s.pop_back();
        return s;
    }

    static std::string strip_host_port(std::string host) {
        host = lower_ascii(host);
        size_t port_pos = host.find(':');
        if (port_pos != std::string::npos) host.resize(port_pos);
        return host;
    }

    static bool host_is_or_under(const std::string& host, const char* domain) {
        std::string h = strip_host_port(host);
        std::string d(domain);
        if (h == d) return true;
        return h.size() > d.size() &&
            h.compare(h.size() - d.size(), d.size(), d) == 0 &&
            h[h.size() - d.size() - 1] == '.';
    }

    static std::string classify(const std::string& host) {
        if (host_is_or_under(host, "conn-service-cn-04.allawntech.com") ||
            host_is_or_under(host, "conn-service-cn-05.allawntech.com") ||
            host_is_or_under(host, "traffic-monitor-cn.allawntech.com") ||
            host_is_or_under(host, "weather-server.allawntech.com") ||
            host_is_or_under(host, "pantanal-intelli-cn.allawntech.com") ||
            host_is_or_under(host, "allawntech.com")) {
            return "oppo_allawn";
        }
        if (host_is_or_under(host, "obus-cn.dc.heytapmobi.com") ||
            host_is_or_under(host, "obus-dc20123-cn.heytapmobi.com") ||
            host_is_or_under(host, "httpdns.push.heytapmobi.com") ||
            host_is_or_under(host, "cloudconf-app-cn.heytapmobi.com") ||
            host_is_or_under(host, "dc-dragate-cn.heytapmobi.com") ||
            host_is_or_under(host, "nebula-api-cn.heytapmobi.com") ||
            host_is_or_under(host, "push-ads-cn.heytapmobi.com") ||
            host_is_or_under(host, "heytapmobi.com") ||
            host_is_or_under(host, "heytapmobile.com") ||
            host_is_or_under(host, "coloros.com") ||
            host_is_or_under(host, "oppomobile.com") ||
            host_is_or_under(host, "oppo.com")) {
            return "oppo_heytap";
        }
        if (host_is_or_under(host, "connectivitycheck.gstatic.com") ||
            host_is_or_under(host, "connectivitycheck.android.com") ||
            host_is_or_under(host, "clients3.google.com") ||
            host_is_or_under(host, "clients4.google.com") ||
            host_is_or_under(host, "www.google.com") ||
            host_is_or_under(host, "www.google.cn") ||
            host_is_or_under(host, "developers.google.cn") ||
            host_is_or_under(host, "google.cn") ||
            host_is_or_under(host, "gstatic.com")) {
            return "android_google";
        }
        if (host_is_or_under(host, "mtalk.google.com") ||
            strip_host_port(host).find("-mtalk.google.com") != std::string::npos ||
            host_is_or_under(host, "googleapis.com") ||
            host_is_or_under(host, "android.com") ||
            host_is_or_under(host, "gvt1.com") ||
            host_is_or_under(host, "gvt2.com")) {
            return "android_google_api";
        }
        if (host_is_or_under(host, "captive.apple.com") ||
            host_is_or_under(host, "www.apple.com") ||
            host_is_or_under(host, "www.appleiphonecell.com") ||
            host_is_or_under(host, "apple.com")) {
            return "apple";
        }
        if (host_is_or_under(host, "msftconnecttest.com") ||
            host_is_or_under(host, "msftncsi.com")) {
            return "microsoft";
        }
        if (host_is_or_under(host, "connectivitycheck.platform.hicloud.com") ||
            host_is_or_under(host, "connectivitycheck.platform.hihonorcloud.com")) {
            return "huawei";
        }
        if (host_is_or_under(host, "connect.rom.miui.com")) {
            return "miui";
        }
        if (host_is_or_under(host, "wifi.vivo.com.cn") ||
            host_is_or_under(host, "vivo.com.cn")) {
            return "vivo";
        }
        return "";
    }

    void cleanup_locked(uint64_t now) {
        for (auto it = m_hints.begin(); it != m_hints.end();) {
            if (it->second.expire_tick <= now) it = m_hints.erase(it);
            else ++it;
        }
    }

    std::mutex m_mutex;
    std::unordered_map<uint32_t, DnsProbeHint> m_hints;
};
