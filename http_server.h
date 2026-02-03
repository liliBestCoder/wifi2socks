#pragma once
#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <map>

class SimpleHttpServer {
public:
    static SimpleHttpServer& instance();
    
    void start(uint16_t port);
    void stop();

private:
    SimpleHttpServer();
    ~SimpleHttpServer();

    void worker_loop();
    void handle_client(uint64_t client_socket);
    
    // Handlers
    std::string handle_stats();
    std::string handle_rules_get();
    std::string handle_rules_update(const std::string& type, const std::string& body);
    std::string handle_proxy_check();

    // Helpers
    struct HttpRequest {
        std::string method;
        std::string path;
        std::string body;
        std::map<std::string, std::string> headers;
    };
    
    bool parse_request(const std::string& raw, HttpRequest& req);
    void send_response(uint64_t sock, int status, const std::string& content_type, const std::string& body);
    // Updated signature: takes json and key
    std::vector<std::string> json_parse_list(const std::string& json, const std::string& key);

    std::atomic<bool> m_running;
    std::thread m_thread;
    uint64_t m_listen_socket;
};
