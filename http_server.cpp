#define _WIN32_WINNT 0x0A00 // Windows 10
#include <winsock2.h>
#include <ws2tcpip.h>

#include "http_server.h"
#include "app_config.h"
#include "traffic_manager.h"
#include "rule_manager.h"
#include "wifi_ap.h"
#include "ics_manager.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <chrono>
#include <algorithm>
#include <fstream>
#include <thread>

#pragma comment(lib, "Ws2_32.lib")

SimpleHttpServer & SimpleHttpServer::instance() {
    static SimpleHttpServer inst;
    return inst;
}

SimpleHttpServer::SimpleHttpServer() : m_running(false), m_listen_socket(INVALID_SOCKET) {}

SimpleHttpServer::~SimpleHttpServer() {
    stop();
}

void SimpleHttpServer::start(uint16_t port) {
    if (m_running.exchange(true)) return;

    m_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listen_socket == INVALID_SOCKET) {
        m_running = false;
        return;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(m_listen_socket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(m_listen_socket);
        m_listen_socket = INVALID_SOCKET;
        m_running = false;
        return;
    }

    if (listen(m_listen_socket, 5) == SOCKET_ERROR) {
        closesocket(m_listen_socket);
        m_listen_socket = INVALID_SOCKET;
        m_running = false;
        return;
    }

    m_thread = std::thread(&SimpleHttpServer::worker_loop, this);
    printf("[HTTP] API Server listening on port %d\n", port);
}

void SimpleHttpServer::stop() {
    if (!m_running.exchange(false)) return;
    if (m_listen_socket != INVALID_SOCKET) {
        closesocket(m_listen_socket);
        m_listen_socket = INVALID_SOCKET;
    }
    if (m_thread.joinable()) m_thread.join();
}

void SimpleHttpServer::worker_loop() {
    while (m_running) {
        sockaddr_in client_addr;
        int len = sizeof(client_addr);
        SOCKET client_sock = accept(m_listen_socket, (sockaddr*)&client_addr, &len);

        if (client_sock == INVALID_SOCKET) {
            if (!m_running) break;
            continue;
        }

        std::thread([this, client_sock]() {
            handle_client(client_sock);
            }).detach();
    }
}

static std::vector<std::string> split_str(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

void SimpleHttpServer::handle_client(uint64_t s) {
    SOCKET sock = (SOCKET)s;
    char buffer[4096];
    int r = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (r <= 0) { closesocket(sock); return; }
    buffer[r] = 0;

    std::string raw(buffer);
    HttpRequest req;

    size_t line1_end = raw.find("\r\n");
    if (line1_end == std::string::npos) { closesocket(sock); return; }

    std::string line1 = raw.substr(0, line1_end);
    std::vector<std::string> parts = split_str(line1, ' ');
    if (parts.size() >= 2) {
        req.method = parts[0];
        req.path = parts[1];
    }

    size_t body_pos = raw.find("\r\n\r\n");
    if (body_pos != std::string::npos) {
        req.body = raw.substr(body_pos + 4);
    }

    std::string resp;
    int status = 200;

    if (req.path == "/stats") {
        resp = handle_stats();
    }
    else if (req.path == "/rules") {
        resp = handle_rules_get();
    }
    else if (req.path == "/rules/direct") {
        resp = handle_rules_update("direct", req.body);
    }
    else if (req.path == "/rules/block") {
        resp = handle_rules_update("block", req.body);
    }
    else if (req.path == "/rules/proxy") {
        resp = handle_rules_update("proxy", req.body);
    }
    else if (req.path == "/check") {
        resp = handle_proxy_check();
    }
    else if (req.path == "/logs") {
        resp = handle_logs_get();
    }
    else if (req.path == "/start") {
        resp = handle_start();
    }
    else if (req.path == "/stop") {
        resp = handle_stop();
    }
    else {
        status = 404;
        resp = "{\"error\": \"Not Found\"}";
    }

    send_response(sock, status, "application/json", resp);
    closesocket(sock);
}

void SimpleHttpServer::send_response(uint64_t s, int status, const std::string& content_type, const std::string& body) {
    SOCKET sock = (SOCKET)s;
    std::stringstream ss;
    ss << "HTTP/1.1 " << status << " OK\r\n";
    ss << "Content-Type: " << content_type << "\r\n";
    ss << "Content-Length: " << body.size() << "\r\n";
    ss << "Connection: close\r\n";
    ss << "Access-Control-Allow-Origin: *\r\n";
    ss << "\r\n";

    std::string h = ss.str();
    send(sock, h.c_str(), (int)h.size(), 0);
    send(sock, body.c_str(), (int)body.size(), 0);
}

std::string SimpleHttpServer::handle_stats() {
    return TrafficManager::instance().get_json_stats();
}

std::string SimpleHttpServer::handle_rules_get() {
    std::stringstream ss;
    ss << "{";

    auto list_to_json = [](const std::string& name, const std::vector<std::string>& list) {
        std::stringstream s;
        s << \"" << name << "\":[";
        for (size_t i = 0; i < list.size(); ++i) {
            s << \"" << list[i] << \""";
            if (i < list.size() - 1) s << ",";
        }
        s << "]";
        return s.str();
    };

    ss << list_to_json("direct_ip", g_config.direct_ip_list) << ",";
    ss << list_to_json("direct_domain", g_config.direct_domain_list) << ",";
    ss << list_to_json("block_ip", g_config.block_ip_list) << ",";
    ss << list_to_json("block_domain", g_config.block_domain_list) << ",";
    ss << list_to_json("proxy_ip", g_config.proxy_ip_list) << ",";
    ss << list_to_json("proxy_domain", g_config.proxy_domain_list);

    ss << "}";
    return ss.str();
}

std::vector<std::string> SimpleHttpServer::json_parse_list(const std::string& json, const std::string& key) {
    std::vector<std::string> res;
    std::string pattern = \"" + key + \"\";
    size_t key_pos = json.find(pattern);
    if (key_pos == std::string::npos) return res;

    size_t start_bracket = json.find('[', key_pos);
    if (start_bracket == std::string::npos) return res;

    size_t end_bracket = json.find(']', start_bracket);
    if (end_bracket == std::string::npos) return res;

    std::string content = json.substr(start_bracket + 1, end_bracket - start_bracket - 1);

    std::stringstream ss(content);
    std::string segment;
    while (std::getline(ss, segment, ',')) {
        size_t first = segment.find('"');
        size_t last = segment.rfind('"');
        if (first != std::string::npos && last != std::string::npos && last > first) {
            res.push_back(segment.substr(first + 1, last - first - 1));
        }
    }
    return res;
}

std::string SimpleHttpServer::handle_rules_update(const std::string& type, const std::string& body) {
    std::vector<std::string> ips = json_parse_list(body, "ip");
    std::vector<std::string> domains = json_parse_list(body, "domain");

    if (type == "direct") {
        RuleManager::instance().update_direct_list(ips, domains);
    }
    else if (type == "block") {
        RuleManager::instance().update_block_list(ips, domains);
    }
    else if (type == "proxy") {
        RuleManager::instance().update_proxy_list(ips, domains);
    }

    return "{\"status\":\"ok\"}";
}

std::string SimpleHttpServer::handle_proxy_check() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return "{\"state\":\"down\",\"error\":\"socket_failed\"}";

    DWORD timeout = 4000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, g_config.proxy_ip.c_str(), &addr.sin_addr);
    addr.sin_port = htons(g_config.proxy_port);

    auto start = std::chrono::steady_clock::now();

    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return "{\"state\":\"down\",\"error\":\"proxy_unreachable\"}";
    }

    std::string connect_req = "CONNECT www.google.com:80 HTTP/1.1\r\nProxy-Connection: Keep-Alive\r\n\r\n";
    if (send(s, connect_req.c_str(), (int)connect_req.size(), 0) <= 0) {
        closesocket(s);
        return "{\"state\":\"down\",\"error\":\"send_connect_failed\"}";
    }

    char buf[2048];
    memset(buf, 0, sizeof(buf));
    int r = recv(s, buf, sizeof(buf) - 1, 0);

    if (r <= 0 || !strstr(buf, "200 Connection established") && !strstr(buf, "200 OK")) {
        closesocket(s);
        return "{\"state\":\"down\",\"error\":\"tunnel_failed\"}";
    }

    std::string probe_req = "HEAD /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    send(s, probe_req.c_str(), (int)probe_req.size(), 0);

    memset(buf, 0, sizeof(buf));
    r = recv(s, buf, sizeof(buf) - 1, 0);
    auto end = std::chrono::steady_clock::now();
    closesocket(s);

    if (r > 0) {
        buf[r] = 0;
        if (strstr(buf, "HTTP/1.1 204") || strstr(buf, "HTTP/1.1 200")) {
            long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            return "{\"state\":\"up\",\"delay\":" + std::to_string(ms) + "}";
        }
    }

    return "{\"state\":\"down\",\"error\":\"target_no_response\"}";
}

std::string SimpleHttpServer::handle_logs_get() {
    std::ifstream file("wifi2socks.log", std::ios::binary);
    if (!file) return "[]";

    file.seekg(0, std::ios::end);
    long long current_size = file.tellg();

    if (m_last_log_pos == 0 && current_size > 5000) {
        m_last_log_pos = current_size - 5000;
    }

    if (current_size <= m_last_log_pos) {
        return "[]";
    }

    file.seekg(m_last_log_pos);

    std::string new_content;
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        new_content.append(buffer, (size_t)file.gcount());
    }

    m_last_log_pos = current_size;

    std::stringstream ss;
    ss << "[";
    std::stringstream content_ss(new_content);
    std::string line;
    bool first = true;
    while (std::getline(content_ss, line)) {
        if (line.empty()) continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!first) ss << ",";

        std::string escaped;
        for (char c : line) {
            if (c == '"') escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else escaped += c;
        }

        ss << "\"" << escaped << "\"";
        first = false;
    }
    ss << "]";

    return ss.str();
}

extern std::atomic<bool> g_tap_running;

std::string SimpleHttpServer::handle_start() {
    g_tap_running = true;
    printf("[HTTP] Command Received: START TAP and WiFi.\n");
    try {
        WiFiAPManager::instance().Start();
        
        // Wait for adapter to appear
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        
        if (IcsManager::EnableICS(L"wifi2socks", L"Microsoft Wi-Fi Direct Virtual Adapter")) {
             printf("[HTTP] ICS Enabled.\n");
        } else {
             // Fallback for older Windows or Hosted Network
             printf("[HTTP] ICS Enable Failed. Trying fallback description...\n");
             if (IcsManager::EnableICS(L"wifi2socks", L"Microsoft Hosted Network Virtual Adapter")) {
                 printf("[HTTP] ICS Enabled (Fallback).\n");
             }
        }
    }
    catch (const std::exception& e) {
        printf("WiFi Start Error: %s\n", e.what());
    }
    return "{\"status\":\"ok\",\"action\":\"started\"}";
}

std::string SimpleHttpServer::handle_stop() {
    if (g_tap_running.exchange(false) == true) {
        printf("[HTTP] Command Received: STOP TAP and WiFi.\n");
        try {
            WiFiAPManager::instance().Stop();
        }
        catch (const std::exception& e) {
            printf("WiFi Stop Error: %s\n", e.what());
        }
    }
    return "{\"status\":\"ok\",\"action\":\"stopped\"}";
}
