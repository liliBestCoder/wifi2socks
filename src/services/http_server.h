#pragma once
#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <map>

class SimpleHttpServer {
public:
    static SimpleHttpServer& instance();
    
    void start(uint16_t port);
    void stop();
   

private:
    SimpleHttpServer();
    ~SimpleHttpServer();

    std::vector<std::thread> m_workers;

    // 客户端任务队列
    std::queue<SOCKET> m_task_queue;
    std::mutex m_queue_mtx;
    std::condition_variable m_queue_cv;
    long long m_last_log_pos = 0;

    // 线程池大小，可调整
    int m_thread_count = 8;

    void worker_loop();
    void worker_thread_loop();
    void handle_client(uint64_t client_socket);
    
    // Handlers
    std::string handle_stats();
    std::string handle_rules_get();
    std::string handle_rules_update(const std::string& type, const std::string& body);
    std::string handle_proxy_check();
    std::string handle_geoip_query(const std::string& path);
    std::string handle_logs_get();
    std::string handle_start();
    std::string handle_stop();

    // Helpers
    struct HttpRequest {
        std::string method;
        std::string path;
        std::string body;
        std::map<std::string, std::string> headers;
    };
    
    bool parse_request(const std::string& raw, HttpRequest& req);
    void send_response(uint64_t sock, int status, const std::string& content_type, const std::string& body);
    std::vector<std::string> json_parse_list(const std::string& json, const std::string& key);

    std::atomic<bool> m_running;
    std::thread m_thread;
    uint64_t m_listen_socket;
};