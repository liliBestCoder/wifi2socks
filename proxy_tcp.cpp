#include "proxy_tcp.h"
#include "logger.h"
#include "app_config.h"
#include "tls_parser.h"
#include "rule_manager.h"
#include "geo_checker.h"
#include "dns_probe_tracker.h"
#include <WS2tcpip.h>
#include <mstcpip.h>
#include <algorithm>
#include <cctype>

// --- IoBuffer Pool for high performance (Thread Local to avoid lock contention) ---
struct ThreadLocalTcpPool {
    std::vector<ProxyTCP::IoBuffer*> pool;
    ~ThreadLocalTcpPool() {
        for (auto* b : pool) delete b;
        pool.clear();
    }
};

static thread_local ThreadLocalTcpPool t_tcp_pool;

// --- Static Registry ---
std::mutex ProxyTCP::g_sessions_mtx;
std::vector<std::weak_ptr<ProxyTCP>> ProxyTCP::g_sessions;
std::atomic<size_t> ProxyTCP::g_client_queue_bytes{ 0 };
std::atomic<size_t> ProxyTCP::g_remote_queue_bytes{ 0 };
std::atomic<int> ProxyTCP::g_pressure_level{ 0 };
std::atomic<uint64_t> ProxyTCP::g_pressure_reject_tcp{ 0 };
static std::atomic<uint64_t> g_tcp_session_seq{ 1 };

static bool looks_like_tls_client_hello(const uint8_t* data, size_t len) {
    return len >= 6 && data[0] == 0x16 && data[5] == 0x01;
}

static std::string first_bytes_hex(const uint8_t* data, size_t len, size_t max_len = 16) {
    static const char* hex = "0123456789abcdef";
    size_t n = (std::min)(len, max_len);
    std::string out;
    out.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        if (i) out.push_back(' ');
        unsigned char c = data[i];
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0F]);
    }
    return out;
}

static bool is_server_first_eager_port(uint16_t port) {
    return std::find(g_config.server_first_eager_ports.begin(), g_config.server_first_eager_ports.end(), port) != g_config.server_first_eager_ports.end();
}

static std::string lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static std::string strip_host_port(std::string host) {
    size_t port_pos = host.find(':');
    if (port_pos != std::string::npos) host.resize(port_pos);
    return lower_ascii(host);
}

static bool host_is_or_under(const std::string& host, const char* domain) {
    std::string d(domain);
    if (host == d) return true;
    return host.size() > d.size() &&
        host.compare(host.size() - d.size(), d.size(), d) == 0 &&
        host[host.size() - d.size() - 1] == '.';
}

size_t ProxyTCP::high_water_mark() {
    return lower_ascii(g_config.ap_mode) == "wired_ap" ? 4 * 1024 * 1024 : 1024 * 1024;
}

size_t ProxyTCP::low_water_mark() {
    return lower_ascii(g_config.ap_mode) == "wired_ap" ? 1 * 1024 * 1024 : 256 * 1024;
}

int ProxyTCP::pressure_level() {
    size_t client_q = g_client_queue_bytes.load(std::memory_order_relaxed);
    size_t remote_q = g_remote_queue_bytes.load(std::memory_order_relaxed);
    if (client_q >= 4 * 1024 * 1024 || remote_q >= 4 * 1024 * 1024) return 2;
    if (client_q >= 2 * 1024 * 1024 || remote_q >= 2 * 1024 * 1024) return 1;
    int logged_level = g_pressure_level.load(std::memory_order_relaxed);
    if (logged_level > 0 && (client_q >= 768 * 1024 || remote_q >= 768 * 1024)) return 1;
    return 0;
}

bool ProxyTCP::pressure_high() {
    return pressure_level() >= 1;
}

bool ProxyTCP::pressure_critical() {
    return pressure_level() >= 2;
}

void ProxyTCP::add_client_queue_bytes(size_t bytes) {
    if (bytes) g_client_queue_bytes.fetch_add(bytes, std::memory_order_relaxed);
}

void ProxyTCP::sub_client_queue_bytes(size_t bytes) {
    if (!bytes) return;
    size_t cur = g_client_queue_bytes.load(std::memory_order_relaxed);
    while (cur != 0) {
        size_t next = cur > bytes ? cur - bytes : 0;
        if (g_client_queue_bytes.compare_exchange_weak(cur, next, std::memory_order_relaxed)) break;
    }
}

void ProxyTCP::add_remote_queue_bytes(size_t bytes) {
    if (bytes) g_remote_queue_bytes.fetch_add(bytes, std::memory_order_relaxed);
}

void ProxyTCP::sub_remote_queue_bytes(size_t bytes) {
    if (!bytes) return;
    size_t cur = g_remote_queue_bytes.load(std::memory_order_relaxed);
    while (cur != 0) {
        size_t next = cur > bytes ? cur - bytes : 0;
        if (g_remote_queue_bytes.compare_exchange_weak(cur, next, std::memory_order_relaxed)) break;
    }
}

void ProxyTCP::reset_queue_pressure_bytes() {
    sub_client_queue_bytes(m_client_write_queue_size);
    sub_remote_queue_bytes(m_remote_write_queue_size);
    m_client_write_queue_size = 0;
    m_remote_write_queue_size = 0;
}

static bool is_known_connectivity_check_host(const std::string& host_header) {
    std::string host = strip_host_port(host_header);
    return host_is_or_under(host, "connectivitycheck.gstatic.com") ||
        host_is_or_under(host, "www.gstatic.com") ||
        host_is_or_under(host, "www.google.com") ||
        host_is_or_under(host, "www.google.cn") ||
        host_is_or_under(host, "clients3.google.com") ||
        host_is_or_under(host, "clients4.google.com") ||
        host_is_or_under(host, "connectivitycheck.android.com") ||
        host_is_or_under(host, "www.android.com") ||
        host_is_or_under(host, "connectivitycheck.platform.hicloud.com") ||
        host_is_or_under(host, "connectivitycheck.platform.hihonorcloud.com") ||
        host_is_or_under(host, "connect.rom.miui.com") ||
        host_is_or_under(host, "wifi.vivo.com.cn") ||
        host_is_or_under(host, "conn-service-cn-04.allawntech.com") ||
        host_is_or_under(host, "conn-service-cn-05.allawntech.com") ||
        host_is_or_under(host, "dc-dragate-cn.heytapmobi.com") ||
        host_is_or_under(host, "www.msftconnecttest.com") ||
        host_is_or_under(host, "www.msftncsi.com") ||
        host_is_or_under(host, "captive.apple.com") ||
        host_is_or_under(host, "www.apple.com") ||
        host_is_or_under(host, "www.appleiphonecell.com") ||
        host_is_or_under(host, "www.itools.info") ||
        host_is_or_under(host, "www.airport.us") ||
        host_is_or_under(host, "www.ibook.info") ||
        host == g_config.gateway_ip;
}

static bool is_netcheck_observed_host(const std::string& host_header) {
    std::string host = strip_host_port(host_header);
    return is_known_connectivity_check_host(host) ||
        host_is_or_under(host, "google.com") ||
        host_is_or_under(host, "google.cn") ||
        host_is_or_under(host, "gstatic.com") ||
        host_is_or_under(host, "googleapis.com") ||
        host_is_or_under(host, "gvt1.com") ||
        host_is_or_under(host, "gvt2.com") ||
        host_is_or_under(host, "android.com") ||
        host_is_or_under(host, "apple.com") ||
        host_is_or_under(host, "msftconnecttest.com") ||
        host_is_or_under(host, "msftncsi.com") ||
        host_is_or_under(host, "allawntech.com") ||
        host_is_or_under(host, "heytapmobi.com") ||
        host_is_or_under(host, "heytapmobile.com") ||
        host_is_or_under(host, "coloros.com") ||
        host_is_or_under(host, "oppomobile.com") ||
        host_is_or_under(host, "oppo.com") ||
        host_is_or_under(host, "hicloud.com") ||
        host_is_or_under(host, "hihonorcloud.com") ||
        host_is_or_under(host, "miui.com") ||
        host_is_or_under(host, "vivo.com.cn");
}

static std::string classify_probe_host(const std::string& host_header) {
    std::string host = strip_host_port(host_header);
    if (host.empty()) return "";
    if (host == g_config.gateway_ip) return "gateway";
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
        host.find("-mtalk.google.com") != std::string::npos ||
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

static bool is_youtube_observed_host(const std::string& host_header) {
    std::string host = strip_host_port(host_header);
    return host_is_or_under(host, "youtube.com") ||
        host_is_or_under(host, "youtube.googleapis.com") ||
        host_is_or_under(host, "youtubei.googleapis.com") ||
        host_is_or_under(host, "googlevideo.com") ||
        host_is_or_under(host, "ytimg.com") ||
        host_is_or_under(host, "ggpht.com") ||
        host_is_or_under(host, "youtu.be") ||
        host.find(".googlevideo.com") != std::string::npos;
}

static std::string get_http_first_line(const uint8_t* data, size_t len) {
    const char* raw = (const char*)data;
    const char* line_end = (const char*)memchr(raw, '\n', len);
    if (!line_end) return "";
    std::string line(raw, line_end - raw);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    return line;
}

static std::string make_connectivity_check_response(const uint8_t* data, size_t len, const std::string& host_header) {
    if (!is_http_start(data, len)) return "";
    if (!is_known_connectivity_check_host(host_header)) return "";

    std::string host = strip_host_port(host_header);
    std::string first_line = lower_ascii(get_http_first_line(data, len));
    if (first_line.empty()) return "";

    if (host == g_config.gateway_ip &&
        (first_line == "get / http/1.1" ||
            first_line == "get / http/1.0" ||
            first_line == "head / http/1.1" ||
            first_line == "head / http/1.0")) {
        return
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "Cache-Control: no-store\r\n"
            "\r\n";
    }

    if (first_line.find("/generate_204") != std::string::npos ||
        first_line.find("/generate204") != std::string::npos ||
        first_line.find("/gen_204") != std::string::npos) {
        return
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "Cache-Control: no-store\r\n"
            "\r\n";
    }

    if (first_line.find("/mtuprobe") != std::string::npos ||
        first_line.find("/blank.html") != std::string::npos) {
        return
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Connection: close\r\n"
            "Cache-Control: no-store\r\n"
            "\r\n";
    }

    if (first_line.find("/connecttest.txt") != std::string::npos) {
        return
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 22\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Microsoft Connect Test";
    }

    if (first_line.find("/library/test/success.html") != std::string::npos ||
        first_line.find("/hotspot-detect.html") != std::string::npos) {
        return
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 7\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n"
            "Cache-Control: no-store\r\n"
            "\r\n"
            "Success";
    }

    if (first_line.find("/ncsi.txt") != std::string::npos) {
        return
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 14\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Microsoft NCSI";
    }

    return "";
}

static void enable_keepalive(SOCKET s) {
    int optval = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&optval, sizeof(optval));

    // Windows specific: Configure keepalive intervals
    tcp_keepalive keepalive;
    keepalive.onoff = 1;
    keepalive.keepalivetime = 60000;    // 60 seconds idle before first probe
    keepalive.keepaliveinterval = 10000; // 10 seconds between probes
    DWORD bytes;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &keepalive, sizeof(keepalive), NULL, 0, &bytes, NULL, NULL);
}

ProxyTCP::IoBuffer* ProxyTCP::alloc_buffer(size_t size) {
    ProxyTCP::IoBuffer* buf = nullptr;
    if (!t_tcp_pool.pool.empty()) {
        buf = t_tcp_pool.pool.back();
        t_tcp_pool.pool.pop_back();
    }

    if (!buf) {
        buf = new IoBuffer();
    }

    // Reset buffer state for reuse (minimal reset)
    memset(&buf->overlapped, 0, sizeof(OVERLAPPED));
    buf->on_complete = nullptr;
    buf->next_in_batch = nullptr;
    buf->total_bytes = 0;
    buf->written_bytes = 0;
    buf->state = IoBuffer::IO_READING;
    buf->flags = 0;
    buf->wsa_buf.buf = (char*)buf->buffer;
    buf->wsa_buf.len = (ULONG)sizeof(buf->buffer);

    {
        std::lock_guard<std::mutex> lock(m_buffer_mutex);
        m_live_buffers.insert(buf);
    }

    return buf;
}

void ProxyTCP::free_buffer(IoBuffer* buffer) {
    if (!buffer) return;

    if (!detach_buffer(buffer)) return;
    recycle_buffer(buffer);
}

bool ProxyTCP::detach_buffer(IoBuffer* buffer) {
    if (!buffer) return false;
    std::lock_guard<std::mutex> lock(m_buffer_mutex);
    auto it = m_live_buffers.find(buffer);
    if (it == m_live_buffers.end()) return false;
    m_live_buffers.erase(it);
    return true;
}

bool ProxyTCP::detach_buffer_if_releasable(IoBuffer* buffer) {
    if (!buffer) return false;
    std::lock_guard<std::mutex> lock(m_buffer_mutex);
    auto it = m_live_buffers.find(buffer);
    if (it == m_live_buffers.end()) return false;

    if (buffer->state != IoBuffer::IO_READY &&
        buffer->state != IoBuffer::IO_DROPPED &&
        buffer->state != IoBuffer::IO_EOF) {
        return false;
    }

    m_live_buffers.erase(it);
    return true;
}

void ProxyTCP::recycle_buffer(IoBuffer* buffer) {
    if (!buffer) return;

    buffer->on_complete = nullptr;
    buffer->next_in_batch = nullptr;

    if (t_tcp_pool.pool.size() < 64) {
        t_tcp_pool.pool.push_back(buffer);
    } else {
        delete buffer;
    }
}

ProxyTCP::ProxyTCP(SOCKET client_socket, OriginalDestination dest)
    : m_client_socket(client_socket), m_remote_socket(INVALID_SOCKET),
    m_original_dest(dest), m_state(INITIAL), m_is_direct(false) {

    m_client_read_paused = false;
    m_remote_read_paused = false;
    m_client_write_queue_size = 0;
    m_remote_write_queue_size = 0;
    m_client_pending_read_count = 0;
    m_remote_pending_read_count = 0;
    m_client_inflight_write_count = 0;
    m_remote_inflight_write_count = 0;

    m_client_eof = false;
    m_remote_eof = false;
    m_client_fin_sent = false;
    m_remote_fin_sent = false;
    m_session_id = g_tcp_session_seq.fetch_add(1);
    m_start_time = GetTickCount64();
    m_last_access_time = m_start_time;
    m_half_close_start_time = 0;
    m_connect_start_time = 0;
    m_remote_connected_time = 0;
    m_proxy_connect_ok_time = 0;
    m_first_client_byte_time = 0;
    m_first_remote_byte_time = 0;
    m_first_remote_payload_time = 0;
    m_dns_hint_domain.clear();
    m_last_client_payload_time = 0;
    m_last_remote_payload_time = 0;
    m_last_probe_stat_time = m_start_time;
    m_last_probe_c2r_bytes = 0;
    m_last_probe_r2c_bytes = 0;
    m_last_youtube_stat_time = m_start_time;
    m_last_youtube_c2r_bytes = 0;
    m_last_youtube_r2c_bytes = 0;

    if (m_client_socket != INVALID_SOCKET) {
        sockaddr_in peer = {};
        int peer_len = sizeof(peer);
        if (getpeername(m_client_socket, (sockaddr*)&peer, &peer_len) == 0) {
            m_nat_key = NatManager::make_key(peer.sin_addr.s_addr, peer.sin_port);
            m_has_nat_key = true;
        }

        int optval = 1;
        setsockopt(m_client_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&optval, sizeof(optval));
        enable_keepalive(m_client_socket);
    }
}

ProxyTCP::~ProxyTCP() {
    close_session();
}

void ProxyTCP::start() {
    auto self = shared_from_this();

    {
        std::lock_guard<std::mutex> lock(g_sessions_mtx);
        g_sessions.push_back(self);
    }

    bool eager_connect_server_first = false;
    uint16_t dest_port = ntohs(m_original_dest.port);
    if (is_server_first_eager_port(dest_port)) {
        uint32_t ip_h = ntohl(m_original_dest.ip);
        RouteAction rule = RuleManager::instance().match_ip(ip_h);
        if (GeoChecker::is_private_ip(ip_h) || rule == RouteAction::DIRECT) m_is_direct = true;
        else if (rule == RouteAction::PROXY) m_is_direct = false;
        else if (rule == RouteAction::BLOCK) {
            LOG_INFO("[TCP] Blocking SSH IP");
            close_session();
            return;
        }
        else m_is_direct = GeoChecker::instance().is_cn_ip(ip_h);
        LOG_INFO("[TCP] Server-first eager connect enabled for port %u", dest_port);
        eager_connect_server_first = true;
    }

    WorkerPool::instance().add_socket(m_client_socket, nullptr, nullptr, false, [this, self]() {
        post_reads(m_client_socket);
    });

    if (eager_connect_server_first) {
        connect_remote();
    }
}

void ProxyTCP::connect_remote() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state != INITIAL) return;
        m_state = CONNECTING;
    }

    sockaddr_in remote_addr = { 0 };
    remote_addr.sin_family = AF_INET;

    unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
    char ip_str[INET_ADDRSTRLEN];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

    if (m_is_direct) {
        LOG_INFO("[TCP] Routing DIRECT for %s (IP: %s)", m_detected_domain.empty() ? "(IP)" : m_detected_domain.c_str(), ip_str);
        remote_addr.sin_addr.s_addr = m_original_dest.ip;
        remote_addr.sin_port = m_original_dest.port;
    }
    else {
        LOG_INFO("[TCP] Routing PROXY for %s (IP: %s)", m_detected_domain.empty() ? "(Domain unknown)" : m_detected_domain.c_str(), ip_str);
        inet_pton(AF_INET, g_config.upstream_ip.c_str(), &remote_addr.sin_addr);
        remote_addr.sin_port = htons(g_config.upstream_port);
    }
    m_connect_start_time = GetTickCount64();

    m_remote_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_remote_socket == INVALID_SOCKET) {
        LOG_ERROR("[ProxyTCP] Failed to create remote socket");
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            set_close_reason_unlocked("remote_socket_failed");
        }
        close_session();
        return;
    }

    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &remote_addr.sin_addr, target_ip, INET_ADDRSTRLEN);
    LOG_DEBUG("[ProxyTCP] Connecting to %s:%d (DIRECT=%d, Domain=%s)", 
        target_ip, ntohs(remote_addr.sin_port), m_is_direct, m_detected_domain.c_str());

    // 优化 socket 性能
    int optval = 1;
    setsockopt(m_remote_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&optval, sizeof(optval)); // 禁用 Nagle 算法
    enable_keepalive(m_remote_socket);

    auto self = shared_from_this();
    WorkerPool::instance().connect_async(
        m_remote_socket,
        remote_addr,
        [self]() { self->on_remote_connect(); },
        nullptr, nullptr
    );
}

void ProxyTCP::on_remote_connect() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state == CLOSING) return;

        int error = 0;
        int elen = sizeof(error);
        getsockopt(m_remote_socket, SOL_SOCKET, SO_ERROR, (char*)&error, &elen);
        if (error != 0) {
            LOG_DEBUG("[ProxyTCP] Connect failed with error: %d", error);
            LOG_WARN("[TCPLAT] id=%llu stage=connect_failed route=%s target=%s err=%d connect_ms=%llu",
                (unsigned long long)m_session_id,
                m_is_direct ? "DIRECT" : "PROXY",
                m_detected_domain.empty() ? "(unknown)" : m_detected_domain.c_str(),
                error,
                (unsigned long long)(GetTickCount64() - m_connect_start_time));
            set_close_reason_unlocked("connect_failed:" + std::to_string(error));
            log_probe_unlocked("connect_failed", error);
            close_session_internal();
            return;
        }
        m_remote_connected_time = GetTickCount64();
        LOG_WARN("[TCPLAT] id=%llu stage=connected route=%s target=%s ip=%u.%u.%u.%u:%u connect_ms=%llu queued_c2r=%zu",
            (unsigned long long)m_session_id,
            m_is_direct ? "DIRECT" : "PROXY",
            m_detected_domain.empty() ? "(unknown)" : m_detected_domain.c_str(),
            ((unsigned char*)&m_original_dest.ip)[0],
            ((unsigned char*)&m_original_dest.ip)[1],
            ((unsigned char*)&m_original_dest.ip)[2],
            ((unsigned char*)&m_original_dest.ip)[3],
            ntohs(m_original_dest.port),
            (unsigned long long)(m_remote_connected_time - m_connect_start_time),
            m_remote_write_queue_size);
        log_probe_unlocked("connected");

        if (m_is_direct) {
            m_state = ESTABLISHED;
        }
        else {
            m_state = AWAITING_CONNECT_RESPONSE;
        }
    }

    if (m_is_direct) {
        post_reads(m_remote_socket);
        std::lock_guard<std::mutex> lock(m_mutex);
        process_write_queue(m_remote_socket);
    }
    else {
        std::string target_host = m_detected_domain;
        if (target_host.empty()) {
            unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
            char ip_str[INET_ADDRSTRLEN];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            target_host = ip_str;
        }
        uint16_t target_port = ntohs(m_original_dest.port);
        std::string connect_req = "CONNECT " + target_host + ":" + std::to_string(target_port) + " HTTP/1.1\r\nHost: " + target_host + ":" + std::to_string(target_port) + "\r\n\r\n";

        WorkerPool::instance().send_async(m_remote_socket, (const uint8_t*)connect_req.data(), connect_req.length());
        post_reads(m_remote_socket);
    }
}

void ProxyTCP::on_io_complete(IoBuffer* buffer, DWORD bytes_transferred, int error) {
    auto self = shared_from_this(); // Pin the object to ensure it survives throughout this call

    if (m_state == CLOSING) {
        free_buffer(buffer);
        return;
    }

    // Handle READ completion
    if (buffer->state == IoBuffer::IO_READING) {
        if (error != 0 || bytes_transferred == 0) {
            // EOF or Error
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (buffer->socket == m_client_socket) {
                    m_client_pending_read_count--;
                }
                else {
                    m_remote_pending_read_count--;
                }

                if (error == 0) {
                    // Graceful FIN: Mark as EOF in queue to preserve order
                    buffer->state = IoBuffer::IO_EOF;
                } else {
                    // Actual error: Drop and close immediately
                    buffer->state = IoBuffer::IO_DROPPED;
                    
                    if (error == ERROR_NETNAME_DELETED || error == ERROR_CONNECTION_ABORTED || error == 10038 ||
                        error == 10054 || error == 10053 || error == 10060 || error == 10057 || error == 121 || 
                        error == 1236 || error == 64) {
                        LOG_DEBUG("[TCP] IO closure on socket: %d", error);
                    } else {
                        LOG_ERROR("[TCP] IO Error on socket: %d", error);
                    }
                    const char* side = (buffer->socket == m_client_socket) ? "client" :
                        (buffer->socket == m_remote_socket ? "remote" : "unknown");
                    set_close_reason_unlocked("read_error:" + std::to_string(error) + ":" + side);
                    log_probe_unlocked("read_error", error, side);
                    close_session_internal();
                }
                process_write_queue(m_client_socket);
                process_write_queue(m_remote_socket);
            }
            return;
        }

        buffer->total_bytes = bytes_transferred;
        m_last_access_time = GetTickCount64();
        if (buffer->socket == m_client_socket) {
            if (m_first_client_byte_time == 0) {
                m_first_client_byte_time = GetTickCount64();
                LOG_WARN("[TCPLAT] id=%llu stage=first_client_byte route=%s target=%s since_start_ms=%llu bytes=%lu",
                    (unsigned long long)m_session_id,
                    m_is_direct ? "DIRECT" : "PROXY",
                    m_detected_domain.empty() ? "(unknown)" : m_detected_domain.c_str(),
                    (unsigned long long)(m_first_client_byte_time - m_start_time),
                    (unsigned long)bytes_transferred);
            }
            uint64_t total = m_client_to_remote_bytes.fetch_add(bytes_transferred) + bytes_transferred;
            LOG_DEBUG("[TCPFLOW] id=%llu read client->remote chunk=%lu total=%llu state=%d",
                (unsigned long long)m_session_id,
                (unsigned long)bytes_transferred,
                (unsigned long long)total,
                (int)m_state.load());
        }
        else if (buffer->socket == m_remote_socket) {
            if (m_first_remote_byte_time == 0) {
                m_first_remote_byte_time = GetTickCount64();
                LOG_WARN("[TCPLAT] id=%llu stage=first_remote_byte route=%s target=%s since_connect_ms=%llu since_start_ms=%llu bytes=%lu state=%d",
                    (unsigned long long)m_session_id,
                    m_is_direct ? "DIRECT" : "PROXY",
                    m_detected_domain.empty() ? "(unknown)" : m_detected_domain.c_str(),
                    (unsigned long long)(m_remote_connected_time ? (m_first_remote_byte_time - m_remote_connected_time) : 0),
                    (unsigned long long)(m_first_remote_byte_time - m_start_time),
                    (unsigned long)bytes_transferred,
                    (int)m_state.load());
                log_probe_unlocked("first_remote_byte", 0, std::to_string(bytes_transferred).c_str());
            }
            LOG_DEBUG("[TCPFLOW] id=%llu read remote->client raw_chunk=%lu app_total=%llu state=%d",
                (unsigned long long)m_session_id,
                (unsigned long)bytes_transferred,
                (unsigned long long)m_remote_to_client_bytes.load(),
                (int)m_state.load());
        }
        if (buffer->socket == m_client_socket) {
            handle_client_read_complete(buffer);
        }
        else {
            handle_remote_read_complete(buffer);
        }
    }
    // Handle WRITE completion
    else if (buffer->state == IoBuffer::IO_WRITING) {
        SOCKET write_socket = buffer->socket;

        if (error != 0) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (write_socket == m_client_socket) {
                    if (m_client_inflight_write_count > 0) m_client_inflight_write_count--;
                }
                else if (write_socket == m_remote_socket) {
                    if (m_remote_inflight_write_count > 0) m_remote_inflight_write_count--;
                }
                const char* side = (write_socket == m_client_socket) ? "client" :
                    (write_socket == m_remote_socket ? "remote" : "unknown");
                set_close_reason_unlocked("write_error:" + std::to_string(error) + ":" + side);
                log_probe_unlocked("write_error", error, side);
                if (m_is_netcheck_flow) {
                    LOG_WARN("[NETCHECKFLOW] id=%llu stage=write_error side=%s err=%d host=%s cq=%zu rq=%zu reason=%s",
                        (unsigned long long)m_session_id,
                        side,
                        error,
                        m_detected_domain.empty() ? (!m_dns_hint_domain.empty() ? m_dns_hint_domain.c_str() : "(unknown)") : m_detected_domain.c_str(),
                        m_client_write_queue_size,
                        m_remote_write_queue_size,
                        m_close_reason.c_str());
                }
            }

            IoBuffer* b = buffer;
            while (b) {
                IoBuffer* next = b->next_in_batch;
                free_buffer(b);
                b = next;
            }
            if (error != 10038) {
                close_session();
            }
            return;
        }

        // --- Correctly handle Gather Write completion to prevent data reordering ---
        std::vector<IoBuffer*> unfinished;
        DWORD remaining = bytes_transferred;
        IoBuffer* current = buffer;
        bool need_resume = false;

        {
            std::lock_guard<std::mutex> lock(m_mutex);

            bool to_client = (write_socket == m_client_socket);
            auto& queue = to_client ? m_client_write_queue : m_remote_write_queue;
            auto& queue_size = to_client ? m_client_write_queue_size : m_remote_write_queue_size;
            auto& inflight_count = to_client ? m_client_inflight_write_count : m_remote_inflight_write_count;
            bool& peer_read_paused = to_client ? m_remote_read_paused : m_client_read_paused;

            if (inflight_count > 0) inflight_count--;

            LOG_DEBUG("[TCPFLOW] id=%llu write %s chunk=%lu queue_after=%zu state=%d",
                (unsigned long long)m_session_id,
                to_client ? "remote->client" : "client->remote",
                (unsigned long)bytes_transferred,
                queue_size,
                (int)m_state.load());
            if (m_is_netcheck_flow && to_client) {
                LOG_WARN("[NETCHECKFLOW] id=%llu stage=write_done side=remote_to_client bytes=%lu host=%s cq=%zu rq=%zu state=%d",
                    (unsigned long long)m_session_id,
                    (unsigned long)bytes_transferred,
                    m_detected_domain.empty() ? (!m_dns_hint_domain.empty() ? m_dns_hint_domain.c_str() : "(unknown)") : m_detected_domain.c_str(),
                    m_client_write_queue_size,
                    m_remote_write_queue_size,
                    (int)m_state.load());
            }

            while (current) {
                IoBuffer* next = current->next_in_batch;
                current->next_in_batch = nullptr;

                DWORD contributed = (DWORD)(current->total_bytes - current->written_bytes);
                if (remaining >= contributed) {
                    current->written_bytes = current->total_bytes;
                    remaining -= contributed;
                    if (queue_size >= current->total_bytes) queue_size -= current->total_bytes;
                    else queue_size = 0;
                    if (to_client) sub_client_queue_bytes(current->total_bytes);
                    else sub_remote_queue_bytes(current->total_bytes);

                    current->state = IoBuffer::IO_COMPLETED;
                    free_buffer(current);
                }
                else {
                    current->written_bytes += remaining;
                    remaining = 0;
                    current->state = IoBuffer::IO_READY;
                    unfinished.push_back(current);
                }
                current = next;
            }

            // Push back to front in reverse order to maintain original stream sequence.
            for (int i = (int)unfinished.size() - 1; i >= 0; --i) {
                queue.push_front(unfinished[i]);
            }

            m_last_access_time = GetTickCount64();
            if (queue_size < low_water_mark() && peer_read_paused) {
                peer_read_paused = false;
                need_resume = true;
            }

            process_write_queue(write_socket);
        }

        if (need_resume) {
            if (write_socket == m_client_socket) post_reads(m_remote_socket);
            else post_reads(m_client_socket);
        }
    }
}

void ProxyTCP::set_close_reason_unlocked(const std::string& reason) {
    if (m_close_reason.empty()) m_close_reason = reason;
}

void ProxyTCP::log_probe_unlocked(const char* stage, int error, const char* detail) {
    if (m_probe_class.empty()) return;
    uint64_t now = GetTickCount64();
    uint64_t connect_ms = m_remote_connected_time && m_connect_start_time ? (m_remote_connected_time - m_connect_start_time) : 0;
    uint64_t first_rx_ms = m_first_remote_byte_time && m_remote_connected_time ? (m_first_remote_byte_time - m_remote_connected_time) : 0;
    uint64_t first_payload_ms = m_first_remote_payload_time && m_remote_connected_time ? (m_first_remote_payload_time - m_remote_connected_time) : 0;
    uint64_t last_payload_ago_ms = m_last_remote_payload_time ? (now - m_last_remote_payload_time) : 0;
    const unsigned char* ip = (const unsigned char*)&m_original_dest.ip;
    const char* host = !m_detected_domain.empty() ? m_detected_domain.c_str() :
        (!m_dns_hint_domain.empty() ? m_dns_hint_domain.c_str() : "(unknown)");
    LOG_WARN("[PROBE] id=%llu stage=%s class=%s proto=%s host=%s route=%s ip=%u.%u.%u.%u:%u duration_ms=%llu connect_ms=%llu first_rx_ms=%llu first_payload_ms=%llu last_payload_ago_ms=%llu c2r=%llu r2c=%llu reason=%s cq=%zu rq=%zu err=%d detail=%s",
        (unsigned long long)m_session_id,
        stage ? stage : "-",
        m_probe_class.c_str(),
        m_probe_proto.empty() ? "-" : m_probe_proto.c_str(),
        host,
        m_is_direct ? "DIRECT" : "PROXY",
        ip[0], ip[1], ip[2], ip[3],
        ntohs(m_original_dest.port),
        (unsigned long long)(now - m_start_time),
        (unsigned long long)connect_ms,
        (unsigned long long)first_rx_ms,
        (unsigned long long)first_payload_ms,
        (unsigned long long)last_payload_ago_ms,
        (unsigned long long)m_client_to_remote_bytes.load(std::memory_order_relaxed),
        (unsigned long long)m_remote_to_client_bytes.load(std::memory_order_relaxed),
        m_close_reason.empty() ? "-" : m_close_reason.c_str(),
        m_client_write_queue_size,
        m_remote_write_queue_size,
        error,
        detail ? detail : "-");
}

void ProxyTCP::post_reads(SOCKET socket) {
    if (socket == INVALID_SOCKET) return;

    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_state == CLOSING) return;

    std::atomic<int>* pending_count = (socket == m_client_socket) ? &m_client_pending_read_count : &m_remote_pending_read_count;
    bool paused = (socket == m_client_socket) ? m_client_read_paused : m_remote_read_paused;
    bool eof = (socket == m_client_socket) ? m_client_eof.load() : m_remote_eof.load();

    if (paused || eof) return;

    std::deque<IoBuffer*>* dest_queue = (socket == m_client_socket) ? &m_remote_write_queue : &m_client_write_queue;
    auto self = shared_from_this();

    while (pending_count->load() < MAX_PENDING_READS) {
        if (m_state == CLOSING) break;

        IoBuffer* buf = alloc_buffer();
        if (!buf) break;

        buf->state = IoBuffer::IO_READING;
        buf->socket = socket;
        buf->on_complete = [this, self, buf](DWORD bytes, int err) {
            this->on_io_complete(buf, bytes, err);
        };
        (*pending_count)++;

        dest_queue->push_back(buf);

        DWORD bytes = 0;
        buf->flags = 0; // Reset flags for each call
        int ret = WSARecv(socket, &buf->wsa_buf, 1, &bytes, &buf->flags, &buf->overlapped, NULL);

        if (ret == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                if (err != 10038 && err != 10054 && err != 10053 && err != 10060 && err != 10057) {
                    LOG_ERROR("[ProxyTCP] WSARecv failed: %d", err);
                } else {
                    LOG_DEBUG("[ProxyTCP] WSARecv failed (err: %d, state: %d), closing session", err, (int)m_state.load());
                }
                (*pending_count)--;
                if (!dest_queue->empty() && dest_queue->back() == buf) dest_queue->pop_back();
                free_buffer(buf);
                set_close_reason_unlocked("recv_start_failed:" + std::to_string(err));
                
                // Unlock before calling close_session to avoid deadlocks
                lock.unlock();
                if (err != 10038) close_session();
                return;
            }
        }
    }
}

void ProxyTCP::handle_client_read_complete(IoBuffer* buffer) {
    bool should_connect = false;
    bool handled_locally = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_client_pending_read_count--;

        if (m_state == INITIAL) {
            const uint8_t* buf_data = (const uint8_t*)buffer->buffer;
            size_t buf_size = buffer->total_bytes;
            m_initial_buffer.insert(m_initial_buffer.end(), buf_data, buf_data + buf_size);

            const auto* combined_data = m_initial_buffer.data();
            const auto combined_size = m_initial_buffer.size();

            std::string sni = parse_tls_sni(combined_data, combined_size);
            bool proceed = false;
            std::string decision_reason;
            std::string first_hex = first_bytes_hex(combined_data, combined_size);
            bool http_like = is_http_start(combined_data, combined_size);
            bool tls_like = looks_like_tls_client_hello(combined_data, combined_size);
            if (!sni.empty()) {
                m_detected_domain = sni;
                m_is_netcheck_flow = is_netcheck_observed_host(sni);
                m_is_youtube_flow = is_youtube_observed_host(sni);
                m_probe_class = classify_probe_host(sni);
                m_probe_proto = "TLS";
                log_probe_unlocked("detect");
                proceed = true;
                decision_reason = "sni";
            }
            else {
                std::string host = parse_http_host(combined_data, combined_size);
                if (!host.empty()) {
                    m_initial_http_first_line = get_http_first_line(combined_data, combined_size);
                    m_detected_domain = host;
                    m_is_netcheck_flow = is_netcheck_observed_host(host);
                    m_is_youtube_flow = is_youtube_observed_host(host);
                    m_probe_class = classify_probe_host(host);
                    m_probe_proto = "HTTP";
                    log_probe_unlocked("detect");
                    std::string local_response = make_connectivity_check_response(combined_data, combined_size, host);
                    if (!local_response.empty()) {
                        size_t response_len = (std::min)(local_response.size(), sizeof(buffer->buffer));
                        memcpy(buffer->buffer, local_response.data(), response_len);
                        buffer->total_bytes = response_len;
                        buffer->written_bytes = 0;
                        buffer->state = IoBuffer::IO_READY;

                        m_state = ESTABLISHED;
                        m_is_direct = true;
                        m_initial_buffer.clear();
                        m_remote_eof = true;
                        m_client_write_queue_size += buffer->total_bytes;
                        add_client_queue_bytes(buffer->total_bytes);
                        m_client_write_queue.push_back(buffer);
                        m_remote_to_client_bytes.fetch_add(buffer->total_bytes);
                        set_close_reason_unlocked("connectivity_check_local");

                        LOG_WARN("[NETCHECK] id=%llu stage=local_http host=%s first_line=%s status=%s",
                            (unsigned long long)m_session_id,
                            m_detected_domain.c_str(),
                            m_initial_http_first_line.empty() ? "(incomplete)" : m_initial_http_first_line.c_str(),
                            local_response.find(" 204 ") != std::string::npos ? "204" : "200");
                        LOG_WARN("[NETCHECKFLOW] id=%llu stage=local_response_queued host=%s bytes=%zu first=%s cq=%zu",
                            (unsigned long long)m_session_id,
                            m_detected_domain.c_str(),
                            response_len,
                            first_hex.c_str(),
                            m_client_write_queue_size);
                        log_probe_unlocked("local_http", 0, local_response.find(" 204 ") != std::string::npos ? "204" : "200");
                        process_write_queue(m_client_socket);
                        handled_locally = true;
                    }
                    else {
                        if (m_is_netcheck_flow || is_known_connectivity_check_host(host)) {
                            m_is_http_probe_miss = true;
                            LOG_WARN("[NETCHECK] id=%llu stage=local_miss host=%s first_line=%s known=%d observed=%d",
                                (unsigned long long)m_session_id,
                                host.c_str(),
                                m_initial_http_first_line.empty() ? "(incomplete)" : m_initial_http_first_line.c_str(),
                                is_known_connectivity_check_host(host) ? 1 : 0,
                                m_is_netcheck_flow ? 1 : 0);
                        }
                        proceed = true;
                        decision_reason = "http_host";
                    }
                }
                else if (ntohs(m_original_dest.port) == 22 && combined_size > 0) {
                    proceed = true;
                    decision_reason = "server_first_port_22";
                }
                else if (combined_size > 0 &&
                    !http_like &&
                    !tls_like) {
                    proceed = true;
                    decision_reason = "non_http_tls_first_packet";
                }
                else if (combined_size >= 512) {
                    proceed = true;
                    decision_reason = "fallback_512";
                }
            }

            if (!proceed) {
                uint32_t ip_h = ntohl(m_original_dest.ip);
                LOG_WARN("[TCPSNIWAIT] id=%llu ip=%d.%d.%d.%d:%d buffered=%zu last_chunk=%zu http_like=%d tls_like=%d first=%s waiting=more_initial_bytes",
                    (unsigned long long)m_session_id,
                    (ip_h >> 24) & 0xFF,
                    (ip_h >> 16) & 0xFF,
                    (ip_h >> 8) & 0xFF,
                    ip_h & 0xFF,
                    ntohs(m_original_dest.port),
                    combined_size,
                    buf_size,
                    http_like ? 1 : 0,
                    tls_like ? 1 : 0,
                    first_hex.c_str());
            }

            if (proceed) {
                uint32_t ip_h = ntohl(m_original_dest.ip);
                bool used_dns_hint = false;
                if (m_probe_class.empty()) {
                    DnsProbeHint hint;
                    if (DnsProbeTracker::instance().lookup(m_original_dest.ip, &hint)) {
                        m_dns_hint_domain = hint.domain;
                        m_probe_class = hint.probe_class;
                        m_probe_proto = "DNS-IP";
                        m_is_netcheck_flow = true;
                        m_is_youtube_flow = is_youtube_observed_host(hint.domain);
                        used_dns_hint = true;
                        log_probe_unlocked("dns_ip_hint");
                    }
                }
                LOG_WARN("[TCPDECIDE] id=%llu ip=%d.%d.%d.%d:%d buffered=%zu last_chunk=%zu http_like=%d tls_like=%d sni=%s host=%s dns_hint=%s first=%s reason=%s",
                    (unsigned long long)m_session_id,
                    (ip_h >> 24) & 0xFF,
                    (ip_h >> 16) & 0xFF,
                    (ip_h >> 8) & 0xFF,
                    ip_h & 0xFF,
                    ntohs(m_original_dest.port),
                    combined_size,
                    buf_size,
                    http_like ? 1 : 0,
                    tls_like ? 1 : 0,
                    sni.empty() ? "-" : sni.c_str(),
                    m_detected_domain.empty() ? "-" : m_detected_domain.c_str(),
                    used_dns_hint ? m_dns_hint_domain.c_str() : "-",
                    first_hex.c_str(),
                    decision_reason.empty() ? (m_detected_domain.empty() ? "ip_fallback" : "domain_detected") : decision_reason.c_str());
                if (!m_detected_domain.empty()) {
                    std::string host = m_detected_domain;
                    size_t port_pos = host.find(':');
                    if (port_pos != std::string::npos) host.resize(port_pos);

                    IN_ADDR literal_addr = {};
                    if (inet_pton(AF_INET, host.c_str(), &literal_addr) == 1) {
                        uint32_t ip_h = ntohl(literal_addr.S_un.S_addr);
                        RouteAction rule = RuleManager::instance().match_ip(ip_h);
                        if (GeoChecker::is_private_ip(ip_h) || rule == RouteAction::DIRECT) m_is_direct = true;
                        else if (rule == RouteAction::PROXY) m_is_direct = false;
                        else if (rule == RouteAction::BLOCK) {
                            LOG_INFO("[TCP] Blocking IP host: %s", m_detected_domain.c_str());
                            buffer->state = IoBuffer::IO_DROPPED;
                            close_session_internal(); return;
                        }
                        else { m_is_direct = GeoChecker::instance().is_cn_ip(ip_h); }
                    }
                    else {
                        RouteAction rule = RuleManager::instance().match_domain(m_detected_domain);
                        if (rule == RouteAction::DIRECT) m_is_direct = true;
                        else if (rule == RouteAction::PROXY) m_is_direct = false;
                        else if (rule == RouteAction::BLOCK) {
                            LOG_INFO("[TCP] Blocking domain: %s", m_detected_domain.c_str());
                            buffer->state = IoBuffer::IO_DROPPED;
                            close_session_internal(); return;
                        }
                        else {
                            m_is_direct = GeoChecker::instance().is_cn_domain(m_detected_domain);
                            if (!m_is_direct &&
                                !GeoChecker::instance().is_google_domain(m_detected_domain) &&
                                GeoChecker::instance().is_cn_ip(ntohl(m_original_dest.ip))) {
                                m_is_direct = true;
                            }
                        }
                    }
                }
                else {
                    uint32_t ip_h = ntohl(m_original_dest.ip);
                    RouteAction rule = RuleManager::instance().match_ip(ip_h);
                    if (GeoChecker::is_private_ip(ip_h) || rule == RouteAction::DIRECT) m_is_direct = true;
                    else if (rule == RouteAction::PROXY) m_is_direct = false;
                    else if (rule == RouteAction::BLOCK) {
                        LOG_INFO("[TCP] Blocking IP: %s", m_detected_domain.c_str());
                        buffer->state = IoBuffer::IO_DROPPED;
                        close_session_internal(); return;
                    }
                    else { m_is_direct = GeoChecker::instance().is_cn_ip(ip_h); }
                }

                if (pressure_critical() &&
                    !m_is_netcheck_flow &&
                    (m_detected_domain.empty() || !is_known_connectivity_check_host(m_detected_domain)) &&
                    !GeoChecker::is_private_ip(ntohl(m_original_dest.ip))) {
                    g_pressure_reject_tcp.fetch_add(1, std::memory_order_relaxed);
                    unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
                    LOG_WARN("[PRESSURE] action=reject_tcp_new id=%llu host=%s ip=%u.%u.%u.%u:%u level=%d global_cq=%zu global_rq=%zu buffered=%zu",
                        (unsigned long long)m_session_id,
                        m_detected_domain.empty() ? "(ip)" : m_detected_domain.c_str(),
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                        ntohs(m_original_dest.port),
                        pressure_level(),
                        g_client_queue_bytes.load(std::memory_order_relaxed),
                        g_remote_queue_bytes.load(std::memory_order_relaxed),
                        combined_size);
                    set_close_reason_unlocked("pressure_reject");
                    buffer->state = IoBuffer::IO_DROPPED;
                    close_session_internal();
                    return;
                }

                m_initial_buffer.clear();
                if (m_is_netcheck_flow) {
                    unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
                    const char* netcheck_host = !m_detected_domain.empty() ? m_detected_domain.c_str() :
                        (!m_dns_hint_domain.empty() ? m_dns_hint_domain.c_str() : "(unknown)");
                    LOG_WARN("[NETCHECK] id=%llu stage=route host=%s route=%s ip=%u.%u.%u.%u:%u buffered=%zu local_miss=%d first_line=%s",
                        (unsigned long long)m_session_id,
                        netcheck_host,
                        m_is_direct ? "DIRECT" : "PROXY",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                        ntohs(m_original_dest.port),
                        combined_size,
                        m_is_http_probe_miss ? 1 : 0,
                        m_initial_http_first_line.empty() ? "-" : m_initial_http_first_line.c_str());
                }
                log_probe_unlocked("route", 0, m_initial_http_first_line.empty() ? "-" : m_initial_http_first_line.c_str());
                should_connect = true;
            }
        }

        if (handled_locally) {
            return;
        }

        if (buffer->state != IoBuffer::IO_DROPPED) {
            buffer->state = IoBuffer::IO_READY;
            m_remote_write_queue_size += buffer->total_bytes;
            add_remote_queue_bytes(buffer->total_bytes);
            if (m_remote_write_queue_size >= high_water_mark()) m_client_read_paused = true;
            process_write_queue(m_remote_socket);
        }
        else {
            process_write_queue(m_remote_socket);
        }
    }

    if (should_connect) {
        connect_remote();
    }
    post_reads(m_client_socket);
}

void ProxyTCP::handle_remote_read_complete(IoBuffer* buffer) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_remote_pending_read_count--;

        bool is_handshake_response = false;
        if (m_state == AWAITING_CONNECT_RESPONSE) {
            m_proxy_response_buffer.insert(m_proxy_response_buffer.end(), buffer->buffer, buffer->buffer + buffer->total_bytes);
            const char* crlf2 = "\r\n\r\n";
            auto it = std::search(m_proxy_response_buffer.begin(), m_proxy_response_buffer.end(), crlf2, crlf2 + 4);

            if (it != m_proxy_response_buffer.end()) {
                std::string header(m_proxy_response_buffer.begin(), it + 4);
                if (header.find(" 200 ") != std::string::npos) {
                    m_state = ESTABLISHED;
                    m_proxy_connect_ok_time = GetTickCount64();
                    LOG_WARN("[TCPLAT] id=%llu stage=proxy_connect_200 target=%s connect_to_200_ms=%llu since_start_ms=%llu queued_c2r=%zu",
                        (unsigned long long)m_session_id,
                        m_detected_domain.empty() ? "(unknown)" : m_detected_domain.c_str(),
                        (unsigned long long)(m_remote_connected_time ? (m_proxy_connect_ok_time - m_remote_connected_time) : 0),
                        (unsigned long long)(m_proxy_connect_ok_time - m_start_time),
                        m_remote_write_queue_size);
                    log_probe_unlocked("proxy_connect_200");
                    size_t header_len = std::distance(m_proxy_response_buffer.begin(), it) + 4;
                    m_proxy_response_buffer.clear();

                    if (buffer->total_bytes > header_len) {
                        buffer->total_bytes -= header_len;
                        // Move remaining data to front of buffer
                        memmove(buffer->buffer, buffer->buffer + header_len, buffer->total_bytes);
                    }
                    else {
                        is_handshake_response = true;
                    }

                    process_write_queue(m_remote_socket);
                }
                else {
                    LOG_ERROR("[ProxyTCP] Proxy refused connection: %s", header.c_str());
                    set_close_reason_unlocked("proxy_refused");
                    log_probe_unlocked("proxy_refused", 0, header.c_str());
                    buffer->state = IoBuffer::IO_DROPPED;
                    close_session_internal(); return;
                }
            }
            else {
                is_handshake_response = true;
            }
        }

        if (is_handshake_response) {
            buffer->state = IoBuffer::IO_DROPPED;
        }
        else {
            uint64_t now = GetTickCount64();
            uint64_t total = m_remote_to_client_bytes.fetch_add(buffer->total_bytes) + buffer->total_bytes;
            m_last_remote_payload_time = now;
            if (m_first_remote_payload_time == 0) {
                m_first_remote_payload_time = now;
                if (!m_probe_class.empty()) {
                    log_probe_unlocked("first_remote_payload", 0, std::to_string(buffer->total_bytes).c_str());
                }
                if (m_is_youtube_flow) {
                    LOG_WARN("[YTSTAT] id=%llu stage=first_payload host=%s route=%s since_connect_ms=%llu since_start_ms=%llu chunk=%zu r2c=%llu",
                        (unsigned long long)m_session_id,
                        m_detected_domain.empty() ? "(unknown)" : m_detected_domain.c_str(),
                        m_is_direct ? "DIRECT" : "PROXY",
                        (unsigned long long)(m_remote_connected_time ? (now - m_remote_connected_time) : 0),
                        (unsigned long long)(now - m_start_time),
                        buffer->total_bytes,
                        (unsigned long long)total);
                }
            }
            buffer->state = IoBuffer::IO_READY;
            m_client_write_queue_size += buffer->total_bytes;
            add_client_queue_bytes(buffer->total_bytes);
            if (m_client_write_queue_size >= high_water_mark()) m_remote_read_paused = true;
        }
        process_write_queue(m_client_socket);
    }
    post_reads(m_remote_socket);
}

void ProxyTCP::process_write_queue(SOCKET socket) {
    if (m_state == CLOSING) return;

    if (socket != INVALID_SOCKET) {
        // Remote write requires connection to be established
        if (socket == m_remote_socket && m_state != ESTABLISHED) return;

        std::deque<IoBuffer*>* queue = (socket == m_client_socket) ? &m_client_write_queue : &m_remote_write_queue;
        std::atomic<int>* inflight_count = (socket == m_client_socket) ? &m_client_inflight_write_count : &m_remote_inflight_write_count;

        while (!queue->empty() && inflight_count->load() < MAX_PENDING_WRITES) {
            if (m_state == CLOSING) break;

            IoBuffer* leader = queue->front();

            // If the head is still READING, we must wait to maintain stream order
            if (leader->state == IoBuffer::IO_READING) break;

            queue->pop_front();
            if (leader->state == IoBuffer::IO_DROPPED) {
                free_buffer(leader);
                continue;
            }

            if (leader->state == IoBuffer::IO_EOF) {
                // EOF reached the front of the queue: Set flags in correct order
                uint64_t zero = 0;
                uint64_t now = GetTickCount64();
                m_half_close_start_time.compare_exchange_strong(zero, now);
                if (socket == m_client_socket) {
                    if (!m_remote_eof) {
                        m_remote_eof = true;
                        LOG_DEBUG("[TCP] Remote EOF reached queue head");
                    }
                }
                else {
                    if (!m_client_eof) {
                        m_client_eof = true;
                        LOG_DEBUG("[TCP] Client EOF reached queue head");
                    }
                }
                free_buffer(leader);
                continue;
            }

            if (leader->state == IoBuffer::IO_READY) {
                // --- IMPLEMENT GATHER WRITE (BATCHING) ---
                WSABUF batch_bufs[MAX_GATHER_BATCH];
                batch_bufs[0].buf = (char*)leader->buffer + leader->written_bytes;
                batch_bufs[0].len = (ULONG)(leader->total_bytes - leader->written_bytes);

                IoBuffer* current = leader;
                int count = 1;

                // Gather more ready buffers from queue
                while (count < MAX_GATHER_BATCH && !queue->empty()) {
                    IoBuffer* next = queue->front();
                    if (next->state != IoBuffer::IO_READY) break;

                    queue->pop_front();
                    next->state = IoBuffer::IO_WRITING;
                    next->socket = socket;
                    current->next_in_batch = next;
                    current = next;

                    batch_bufs[count].buf = (char*)next->buffer + next->written_bytes;
                    batch_bufs[count].len = (ULONG)(next->total_bytes - next->written_bytes);
                    count++;
                }

                leader->state = IoBuffer::IO_WRITING;
                leader->socket = socket;
                memset(&leader->overlapped, 0, sizeof(OVERLAPPED));

                auto self = shared_from_this();
                leader->on_complete = [this, self, leader](DWORD bytes, int err) {
                    this->on_io_complete(leader, bytes, err);
                };

                DWORD bytes_sent = 0;
                (*inflight_count)++;
                int ret = WSASend(socket, batch_bufs, count, &bytes_sent, 0, &leader->overlapped, NULL);
                if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
                    int err = WSAGetLastError();
                    if (err == 10054 || err == 10053 || err == 10060 || err == 10057 || err == 10038) {
                        LOG_DEBUG("[ProxyTCP] Send failed (err: %d), closing session", err);
                    }
                    else {
                        LOG_ERROR("[ProxyTCP] WSASend Gather failed: %d", err);
                    }
                    const char* side = (socket == m_client_socket) ? "client" :
                        (socket == m_remote_socket ? "remote" : "unknown");
                    set_close_reason_unlocked("send_start_failed:" + std::to_string(err) + ":" + side);
                    log_probe_unlocked("send_start_failed", err, side);
                    if (m_is_netcheck_flow) {
                        LOG_WARN("[NETCHECKFLOW] id=%llu stage=send_start_failed side=%s err=%d host=%s cq=%zu rq=%zu",
                            (unsigned long long)m_session_id,
                            side,
                            err,
                            m_detected_domain.empty() ? (!m_dns_hint_domain.empty() ? m_dns_hint_domain.c_str() : "(unknown)") : m_detected_domain.c_str(),
                            m_client_write_queue_size,
                            m_remote_write_queue_size);
                    }
                    (*inflight_count)--;
                    IoBuffer* b = leader;
                    while (b) {
                        IoBuffer* n = b->next_in_batch;
                        free_buffer(b);
                        b = n;
                    }
                    close_session_internal(); break;
                }
            }
            else {
                break;
            }
        }

        // After attempting to drain queue, check if we need to send FIN
        bool is_eof = (socket == m_client_socket) ? m_remote_eof.load() : m_client_eof.load();
        std::atomic<bool>* fin_sent = (socket == m_client_socket) ? &m_client_fin_sent : &m_remote_fin_sent;

        if (is_eof && queue->empty() && inflight_count->load() == 0 && !fin_sent->load()) {
            *fin_sent = true;
            uint64_t zero = 0;
            uint64_t fin_time = GetTickCount64();
            m_half_close_start_time.compare_exchange_strong(zero, fin_time);
            LOG_DEBUG("[TCP] Shutdown send on socket %p", (void*)socket);
            shutdown(socket, SD_SEND);
        }
    }

    // Final Closure Logic with Timeout Safeguards: 
    uint64_t now = GetTickCount64();
    uint64_t idle_time = now - m_last_access_time.load();

    // A session is only truly done when:
    // 1. Client has sent EOF AND Proxy has sent FIN to Client.
    // 2. Remote has sent EOF AND Proxy has sent FIN to Remote.
    bool fully_closed = (m_client_eof && m_client_fin_sent && m_remote_eof && m_remote_fin_sent);

    // Safeguard 1: If any side has started closing, don't wait forever for the other side (30s max)
    bool half_closed = (m_client_fin_sent || m_remote_fin_sent || m_client_eof || m_remote_eof);
    uint64_t half_close_start = m_half_close_start_time.load();
    if (half_closed && half_close_start == 0) {
        uint64_t zero = 0;
        m_half_close_start_time.compare_exchange_strong(zero, now);
        half_close_start = m_half_close_start_time.load();
    }

    bool partial_close_timeout = half_closed && half_close_start != 0 &&
        (now - half_close_start > FIN_WAIT_TIMEOUT_MS);

    // Safeguard 2: Absolute idle timeout
    bool absolute_idle_timeout = (idle_time > IDLE_TIMEOUT_MS);

    if (fully_closed || partial_close_timeout || absolute_idle_timeout) {
        if (partial_close_timeout) {
            LOG_DEBUG("[TCP] Closing due to FIN_WAIT timeout.");
            set_close_reason_unlocked("fin_wait_timeout");
        }
        else if (absolute_idle_timeout) {
            LOG_DEBUG("[TCP] Closing due to absolute idle timeout.");
            set_close_reason_unlocked("idle_timeout");
        }
        else {
            LOG_DEBUG("[TCP] Both sides gracefully closed. Cleaning up.");
            set_close_reason_unlocked("graceful");
        }

        close_session_internal();
    }
}

void ProxyTCP::handle_client_write_complete(IoBuffer* buffer) {
    bool need_resume_remote = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_client_inflight_write_count--;
        if (m_client_write_queue_size >= buffer->total_bytes) m_client_write_queue_size -= buffer->total_bytes;
        else m_client_write_queue_size = 0;
        sub_client_queue_bytes(buffer->total_bytes);

        buffer->state = IoBuffer::IO_COMPLETED;
        m_last_access_time = GetTickCount64();
        free_buffer(buffer);

        if (m_client_write_queue_size < low_water_mark() && m_remote_read_paused) {
            m_remote_read_paused = false;
            need_resume_remote = true;
        }
        process_write_queue(m_client_socket);
    }
    if (need_resume_remote) post_reads(m_remote_socket);
}

void ProxyTCP::handle_remote_write_complete(IoBuffer* buffer) {
    bool need_resume_client = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_remote_inflight_write_count--;
        if (m_remote_write_queue_size >= buffer->total_bytes) m_remote_write_queue_size -= buffer->total_bytes;
        else m_remote_write_queue_size = 0;
        sub_remote_queue_bytes(buffer->total_bytes);

        buffer->state = IoBuffer::IO_COMPLETED;
        m_last_access_time = GetTickCount64();
        free_buffer(buffer);

        if (m_remote_write_queue_size < low_water_mark() && m_client_read_paused) {
            m_client_read_paused = false;
            need_resume_client = true;
        }
        process_write_queue(m_remote_socket);
    }
    if (need_resume_client) post_reads(m_client_socket);
}

void ProxyTCP::close_session() {
    std::lock_guard<std::mutex> lock(m_mutex);
    close_session_internal();
}

void ProxyTCP::close_session_internal() {
    if (m_state == CLOSING) return;
    
    unsigned char* ip_bytes = (unsigned char*)&m_original_dest.ip;
    if (m_close_reason.empty()) m_close_reason = "closed";
    uint64_t now = GetTickCount64();
    LOG_WARN("[TCPSTAT] id=%llu route=%s target=%s ip=%d.%d.%d.%d:%d duration_ms=%llu connect_ms=%llu first_rx_ms=%llu c2r=%llu r2c=%llu state=%d reason=%s cq=%zu rq=%zu ci=%d ri=%d c_eof=%d r_eof=%d c_fin=%d r_fin=%d",
        (unsigned long long)m_session_id,
        m_is_direct ? "DIRECT" : "PROXY",
        m_detected_domain.empty() ? "(unknown)" : m_detected_domain.c_str(),
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], ntohs(m_original_dest.port),
        (unsigned long long)(now - m_start_time),
        (unsigned long long)((m_connect_start_time && m_remote_connected_time) ? (m_remote_connected_time - m_connect_start_time) : 0),
        (unsigned long long)((m_remote_connected_time && m_first_remote_byte_time) ? (m_first_remote_byte_time - m_remote_connected_time) : 0),
        (unsigned long long)m_client_to_remote_bytes.load(),
        (unsigned long long)m_remote_to_client_bytes.load(),
        (int)m_state.load(),
        m_close_reason.c_str(),
        m_client_write_queue_size,
        m_remote_write_queue_size,
        m_client_inflight_write_count.load(),
        m_remote_inflight_write_count.load(),
        m_client_eof.load() ? 1 : 0,
        m_remote_eof.load() ? 1 : 0,
        m_client_fin_sent.load() ? 1 : 0,
        m_remote_fin_sent.load() ? 1 : 0);

    log_probe_unlocked("close");

    if (m_is_netcheck_flow) {
        const char* netcheck_host = !m_detected_domain.empty() ? m_detected_domain.c_str() :
            (!m_dns_hint_domain.empty() ? m_dns_hint_domain.c_str() : "(unknown)");
        LOG_WARN("[NETCHECK] id=%llu stage=close host=%s route=%s duration_ms=%llu connect_ms=%llu first_rx_ms=%llu c2r=%llu r2c=%llu reason=%s cq=%zu rq=%zu local_miss=%d first_line=%s",
            (unsigned long long)m_session_id,
            netcheck_host,
            m_is_direct ? "DIRECT" : "PROXY",
            (unsigned long long)(now - m_start_time),
            (unsigned long long)((m_connect_start_time && m_remote_connected_time) ? (m_remote_connected_time - m_connect_start_time) : 0),
            (unsigned long long)((m_remote_connected_time && m_first_remote_byte_time) ? (m_first_remote_byte_time - m_remote_connected_time) : 0),
            (unsigned long long)m_client_to_remote_bytes.load(),
            (unsigned long long)m_remote_to_client_bytes.load(),
            m_close_reason.c_str(),
            m_client_write_queue_size,
            m_remote_write_queue_size,
            m_is_http_probe_miss ? 1 : 0,
            m_initial_http_first_line.empty() ? "-" : m_initial_http_first_line.c_str());
    }

    if (m_is_youtube_flow) {
        LOG_WARN("[YTSTAT] id=%llu stage=close host=%s route=%s duration_ms=%llu connect_ms=%llu first_sock_rx_ms=%llu first_payload_ms=%llu last_payload_ago_ms=%llu c2r=%llu r2c=%llu reason=%s cq=%zu rq=%zu c_eof=%d r_eof=%d c_fin=%d r_fin=%d",
            (unsigned long long)m_session_id,
            m_detected_domain.empty() ? "(unknown)" : m_detected_domain.c_str(),
            m_is_direct ? "DIRECT" : "PROXY",
            (unsigned long long)(now - m_start_time),
            (unsigned long long)((m_connect_start_time && m_remote_connected_time) ? (m_remote_connected_time - m_connect_start_time) : 0),
            (unsigned long long)((m_remote_connected_time && m_first_remote_byte_time) ? (m_first_remote_byte_time - m_remote_connected_time) : 0),
            (unsigned long long)((m_remote_connected_time && m_first_remote_payload_time) ? (m_first_remote_payload_time - m_remote_connected_time) : 0),
            (unsigned long long)(m_last_remote_payload_time ? (now - m_last_remote_payload_time) : 0),
            (unsigned long long)m_client_to_remote_bytes.load(),
            (unsigned long long)m_remote_to_client_bytes.load(),
            m_close_reason.c_str(),
            m_client_write_queue_size,
            m_remote_write_queue_size,
            m_client_eof.load() ? 1 : 0,
            m_remote_eof.load() ? 1 : 0,
            m_client_fin_sent.load() ? 1 : 0,
            m_remote_fin_sent.load() ? 1 : 0);
    }

    m_state = CLOSING;

    if (m_has_nat_key) {
        // WinPkFilter restores outbound TCP packets asynchronously after WSASend
        // completes. Keep the NAT entry briefly after socket close; new inbound
        // connections with the same client port replace stale entries.
        m_has_nat_key = false;
    }

    if (m_client_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_client_socket);
        m_client_socket = INVALID_SOCKET;
    }
    if (m_remote_socket != INVALID_SOCKET) {
        WorkerPool::instance().remove_socket(m_remote_socket);
        m_remote_socket = INVALID_SOCKET;
    }

    reset_queue_pressure_bytes();

    auto clean_safe = [this](std::deque<IoBuffer*>& q) {
        std::vector<IoBuffer*> to_free;
        while (!q.empty()) {
            IoBuffer* buf = q.front();
            q.pop_front();
            // Only free buffers that don't have a pending IO operation.
            // Buffers in IO_READING or IO_WRITING will be freed in on_io_complete when their callbacks fire.
            if (detach_buffer_if_releasable(buf)) {
                to_free.push_back(buf);
            }
        }
        for (auto* buf : to_free) {
            recycle_buffer(buf);
        }
    };
    clean_safe(m_client_write_queue);
    clean_safe(m_remote_write_queue);
}

void ProxyTCP::check_all_timeouts() {
    std::vector<std::shared_ptr<ProxyTCP>> sessions_to_check;
    {
        std::lock_guard<std::mutex> lock(g_sessions_mtx);
        for (auto it = g_sessions.begin(); it != g_sessions.end(); ) {
            if (auto s = it->lock()) {
                sessions_to_check.push_back(s);
                ++it;
            } else {
                it = g_sessions.erase(it);
            }
        }
    }

    for (auto& s : sessions_to_check) {
        std::lock_guard<std::mutex> lock(s->m_mutex);
        // Trigger timeout and closure checks for both directions
        s->process_write_queue(s->m_client_socket);
        s->process_write_queue(s->m_remote_socket);
    }
}

void ProxyTCP::log_global_stats() {
    std::vector<std::shared_ptr<ProxyTCP>> sessions;
    {
        std::lock_guard<std::mutex> lock(g_sessions_mtx);
        for (auto it = g_sessions.begin(); it != g_sessions.end(); ) {
            if (auto s = it->lock()) {
                sessions.push_back(s);
                ++it;
            } else {
                it = g_sessions.erase(it);
            }
        }
    }

    size_t active = 0;
    size_t connecting = 0;
    size_t awaiting = 0;
    size_t established = 0;
    size_t closing = 0;
    size_t proxy_route = 0;
    size_t direct_route = 0;
    size_t half_closed = 0;
    size_t paused = 0;
    size_t no_remote_first_byte = 0;
    size_t remote_queue_bytes = 0;
    size_t client_queue_bytes = 0;
    size_t remote_inflight = 0;
    size_t client_inflight = 0;
    uint64_t max_age_ms = 0;
    uint64_t max_idle_ms = 0;
    uint64_t now = GetTickCount64();
    size_t youtube_active = 0;
    size_t youtube_stalled = 0;

    for (auto& s : sessions) {
        std::lock_guard<std::mutex> lock(s->m_mutex);
        State st = s->m_state.load();
        if (st == CLOSING) {
            closing++;
        } else {
            active++;
        }
        if (st == CONNECTING) connecting++;
        else if (st == AWAITING_CONNECT_RESPONSE) awaiting++;
        else if (st == ESTABLISHED) established++;

        if (s->m_is_direct) direct_route++;
        else proxy_route++;

        if (s->m_client_eof || s->m_remote_eof || s->m_client_fin_sent || s->m_remote_fin_sent) half_closed++;
        if (s->m_client_read_paused || s->m_remote_read_paused) paused++;
        if (!s->m_is_direct && s->m_remote_connected_time != 0 && s->m_first_remote_byte_time == 0) no_remote_first_byte++;

        remote_queue_bytes += s->m_remote_write_queue_size;
        client_queue_bytes += s->m_client_write_queue_size;
        remote_inflight += (size_t)s->m_remote_inflight_write_count.load();
        client_inflight += (size_t)s->m_client_inflight_write_count.load();

        uint64_t age = now - s->m_start_time;
        uint64_t idle = now - s->m_last_access_time.load();
        if (age > max_age_ms) max_age_ms = age;
        if (idle > max_idle_ms) max_idle_ms = idle;

        if (!s->m_probe_class.empty() && st != CLOSING && now - s->m_last_probe_stat_time >= 5000) {
            uint64_t c2r = s->m_client_to_remote_bytes.load();
            uint64_t r2c = s->m_remote_to_client_bytes.load();
            uint64_t win_ms = now - s->m_last_probe_stat_time;
            uint64_t dc2r = c2r - s->m_last_probe_c2r_bytes;
            uint64_t dr2c = r2c - s->m_last_probe_r2c_bytes;
            uint64_t down_bps = win_ms ? (dr2c * 1000ULL / win_ms) : 0;
            uint64_t up_bps = win_ms ? (dc2r * 1000ULL / win_ms) : 0;
            uint64_t first_payload_ms = (s->m_remote_connected_time && s->m_first_remote_payload_time) ? (s->m_first_remote_payload_time - s->m_remote_connected_time) : 0;
            uint64_t last_payload_ago = s->m_last_remote_payload_time ? (now - s->m_last_remote_payload_time) : 0;
            LOG_WARN("[PROBESTAT] id=%llu stage=active class=%s proto=%s host=%s route=%s age_ms=%llu idle_ms=%llu win_ms=%llu dc2r=%llu dr2c=%llu up_Bps=%llu down_Bps=%llu first_payload_ms=%llu last_payload_ago_ms=%llu cq=%zu rq=%zu ci=%d ri=%d",
                (unsigned long long)s->m_session_id,
                s->m_probe_class.c_str(),
                s->m_probe_proto.empty() ? "-" : s->m_probe_proto.c_str(),
                s->m_detected_domain.empty() ? "(unknown)" : s->m_detected_domain.c_str(),
                s->m_is_direct ? "DIRECT" : "PROXY",
                (unsigned long long)age,
                (unsigned long long)idle,
                (unsigned long long)win_ms,
                (unsigned long long)dc2r,
                (unsigned long long)dr2c,
                (unsigned long long)up_bps,
                (unsigned long long)down_bps,
                (unsigned long long)first_payload_ms,
                (unsigned long long)last_payload_ago,
                s->m_client_write_queue_size,
                s->m_remote_write_queue_size,
                s->m_client_inflight_write_count.load(),
                s->m_remote_inflight_write_count.load());
            s->m_last_probe_stat_time = now;
            s->m_last_probe_c2r_bytes = c2r;
            s->m_last_probe_r2c_bytes = r2c;
        }

        if (s->m_is_youtube_flow && st != CLOSING) {
            youtube_active++;
            uint64_t last_payload_ago = s->m_last_remote_payload_time ? (now - s->m_last_remote_payload_time) : 0;
            if (s->m_first_remote_payload_time != 0 && last_payload_ago > 3000) youtube_stalled++;

            if (now - s->m_last_youtube_stat_time >= 5000) {
                uint64_t c2r = s->m_client_to_remote_bytes.load();
                uint64_t r2c = s->m_remote_to_client_bytes.load();
                uint64_t win_ms = now - s->m_last_youtube_stat_time;
                uint64_t dc2r = c2r - s->m_last_youtube_c2r_bytes;
                uint64_t dr2c = r2c - s->m_last_youtube_r2c_bytes;
                uint64_t down_bps = win_ms ? (dr2c * 1000ULL / win_ms) : 0;
                uint64_t up_bps = win_ms ? (dc2r * 1000ULL / win_ms) : 0;
                LOG_WARN("[YTSTAT] id=%llu stage=active host=%s route=%s age_ms=%llu idle_ms=%llu win_ms=%llu dc2r=%llu dr2c=%llu up_Bps=%llu down_Bps=%llu first_payload_ms=%llu last_payload_ago_ms=%llu cq=%zu rq=%zu ci=%d ri=%d",
                    (unsigned long long)s->m_session_id,
                    s->m_detected_domain.empty() ? "(unknown)" : s->m_detected_domain.c_str(),
                    s->m_is_direct ? "DIRECT" : "PROXY",
                    (unsigned long long)age,
                    (unsigned long long)idle,
                    (unsigned long long)win_ms,
                    (unsigned long long)dc2r,
                    (unsigned long long)dr2c,
                    (unsigned long long)up_bps,
                    (unsigned long long)down_bps,
                    (unsigned long long)((s->m_remote_connected_time && s->m_first_remote_payload_time) ? (s->m_first_remote_payload_time - s->m_remote_connected_time) : 0),
                    (unsigned long long)last_payload_ago,
                    s->m_client_write_queue_size,
                    s->m_remote_write_queue_size,
                    s->m_client_inflight_write_count.load(),
                    s->m_remote_inflight_write_count.load());
                s->m_last_youtube_stat_time = now;
                s->m_last_youtube_c2r_bytes = c2r;
                s->m_last_youtube_r2c_bytes = r2c;
            }
        }
    }

    size_t global_cq = g_client_queue_bytes.load(std::memory_order_relaxed);
    size_t global_rq = g_remote_queue_bytes.load(std::memory_order_relaxed);
    int old_pressure = g_pressure_level.load(std::memory_order_relaxed);
    int new_pressure = 0;
    if (global_cq >= 4 * 1024 * 1024 || global_rq >= 4 * 1024 * 1024 || paused >= 6) {
        new_pressure = 2;
    }
    else if (global_cq >= 2 * 1024 * 1024 || global_rq >= 2 * 1024 * 1024 || paused >= 3) {
        new_pressure = 1;
    }
    else if (old_pressure > 0 && (global_cq >= 768 * 1024 || global_rq >= 768 * 1024 || paused > 0)) {
        new_pressure = 1;
    }
    g_pressure_level.store(new_pressure, std::memory_order_relaxed);

    LOG_WARN("[TCPSTATG] sessions=%zu active=%zu connecting=%zu awaiting_proxy=%zu established=%zu closing=%zu proxy=%zu direct=%zu half_closed=%zu paused=%zu no_remote_first_byte=%zu cq_bytes=%zu rq_bytes=%zu ci=%zu ri=%zu pressure=%d pressure_reject_tcp=%llu yt_active=%zu yt_stalled=%zu max_age_ms=%llu max_idle_ms=%llu",
        sessions.size(),
        active,
        connecting,
        awaiting,
        established,
        closing,
        proxy_route,
        direct_route,
        half_closed,
        paused,
        no_remote_first_byte,
        client_queue_bytes,
        remote_queue_bytes,
        client_inflight,
        remote_inflight,
        new_pressure,
        (unsigned long long)g_pressure_reject_tcp.load(std::memory_order_relaxed),
        youtube_active,
        youtube_stalled,
        (unsigned long long)max_age_ms,
        (unsigned long long)max_idle_ms);
}
