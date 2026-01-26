#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "ucb.h"
#include "arp.h"
#include <thread>
#include <set>
#include <mutex>


#define UDP_ADDR "192.168.21.5"


inline uint16_t checksum(const void* p, int len, uint32_t c = 0) {
    const uint16_t* buf = (const uint16_t*)p;
    for (; len > 1; len -= 2) c += *buf++;
    if (len == 1) c += *(const uint8_t*)buf;
    while (c >> 16) c = (c & 0xffff) + (c >> 16);
    return ~uint16_t(c);
}

inline uint16_t udp_cksum(uint32_t s, uint32_t d, const uint8_t* udp, int len) {
    struct PH { uint32_t s, d; uint8_t zero, proto; uint16_t len; } ph = { s,d,0,17,uint16_t(len) };
    uint32_t sum = checksum(&ph, sizeof(ph), 0);
    return checksum(udp, len, sum);
}

static std::mutex g_log_mtx;
template<typename... Args>
static void log_line(const char* fmt, Args... a) {
    std::lock_guard<std::mutex> lk(g_log_mtx);
    printf(fmt, a...);
    printf("\n");
    fflush(stdout);
}

/* 1. 平台出口 */
void platform_send_frame(HANDLE tap, const uint8_t* f, int len) {
    DWORD w; WriteFile(tap, f, len, &w, NULL);
}

/* 线程：把中继回包注回 TAP */
static void udp_relay_to_tap(HANDLE tap, Quad q, SOCKET udpSock) {
    uint8_t buf[2048];
    sockaddr_in from;
    int fromlen = sizeof(from);
    while (true) {
        int r = recvfrom(udpSock, (char*)buf, sizeof(buf), 0, nullptr, nullptr);
        if (r == 0) {
            break;
        }
        else if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) continue; // 可重试
            int err = WSAGetLastError();
            printf("recv error: %d\n", err);
            break;
        }

        /* ② 把收到的裸 DNS/UDP 直接封装成以太/IP/UDP 发回 TAP */
        uint8_t frame[2048];
        memcpy(frame, TAP_MAC, 6);      // 目的：客户端
        memcpy(frame + 6, TAP_MAC, 6);     // 源：TAP
        *(uint16_t*)(frame + 12) = htons(0x0800);

        uint8_t* ip = frame + 14;
        uint8_t* udp = ip + 20;
        memset(ip, 0, 20);
        ip[0] = 0x45;
        *(uint16_t*)(ip + 2) = htons(20 + 8 + r);
        ip[8] = 64;
        ip[9] = IPPROTO_UDP;
        /* 源 = 原来客户端发去的“服务器地址” */
        *(uint32_t*)(ip + 12) = q.dport;
        /* 目的 = 客户端自己 */
        *(uint32_t*)(ip + 16) = q.sport;
        *(uint16_t*)(ip + 10) = checksum(ip, 20);

        *(uint16_t*)(udp + 0) = htons(q.dport);   // 源端口 = 原来客户端发去的端口
        *(uint16_t*)(udp + 2) = htons(q.sport);   // 目的端口 = 客户端源端口
        *(uint16_t*)(udp + 4) = htons(8 + r);
        memcpy(udp + 8, buf, r);
        *(uint16_t*)(udp + 6) = 0;
        *(uint16_t*)(udp + 6) = udp_cksum(q.daddr, q.saddr, udp, 8 + r);

        platform_send_frame(tap, frame, 14 + 20 + 8 + r);

        int pay_len = r;

        /* 新增日志 */
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &q.daddr, src, sizeof(src));
        inet_ntop(AF_INET, &q.saddr, dst, sizeof(dst));
        /* 新增日志：如果是 DNS 就打印明文域名 */
        /* ===== 新增：解析 DNS 应答 ===== */
        /* ---------- 在 udp_relay_to_tap 里替换原来的打印 ---------- */
        auto print_dns_line = [&]() {
            log_line("[UDP-TAP] inject %s:%u -> %s:%u  %d bytes",
                src, q.dport, dst, q.sport, pay_len);
            if (q.dport != 53 || pay_len < 12) return;

            const uint8_t* dns = buf;

            /* ===== 1. 头 ===== */
            uint16_t tid = ntohs(*(uint16_t*)(dns + 0));
            uint16_t flags = ntohs(*(uint16_t*)(dns + 2));
            if (!(flags & 0x8000)) return;          // 只留响应

            uint16_t qdcount = ntohs(*(uint16_t*)(dns + 4));
            uint16_t ancount = ntohs(*(uint16_t*)(dns + 6));

            /* ===== 2. 通用域名解压（支持压缩指针） ===== */
            auto parse_name = [&](int& p, std::string& out) {
                int jumped = 0, offset = 0, max_jump = 5;
                while (p < pay_len) {
                    uint8_t len = dns[p];
                    if (len == 0) { p++; break; }
                    if ((len & 0xC0) == 0xC0) {                // 压缩指针
                        offset = ((len & 0x3F) << 8) | dns[p + 1];
                        if (!jumped) jumped = p + 2;           // 记录返回点
                        p = offset;
                        if (--max_jump < 0) break;             // 防环
                        continue;
                    }
                    p++;
                    if (out.size()) out += '.';
                    out.append((char*)dns + p, len);
                    p += len;
                }
                if (jumped) p = jumped;                          // 回到第一次跳转后
                };

            /* ===== 3. 跳过 Question ===== */
            int pos = 12;
            std::string qname;
            parse_name(pos, qname);              // 解查询名
            pos += 4;                            // 跳过 QTYPE+QCLASS

            /* ===== 4. 收集 Answer ===== */
            std::set<std::string> cnames, ips;
            for (int i = 0; i < ancount && pos < pay_len - 10; ++i) {
                std::string aname;               // Answer 里的名字（通常与查询相同）
                parse_name(pos, aname);          // 跳过 Answer 名

                uint16_t rtype = ntohs(*(uint16_t*)(dns + pos)); pos += 2;
                uint16_t rclass = ntohs(*(uint16_t*)(dns + pos)); pos += 2;
                uint32_t ttl = ntohl(*(uint32_t*)(dns + pos)); pos += 4;
                uint16_t rdlen = ntohs(*(uint16_t*)(dns + pos)); pos += 2;
                if (pos + rdlen > pay_len) break;

                if (rtype == 1 && rdlen == 4) {                       // A 记录
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, dns + pos, ip_str, sizeof(ip_str));
                    ips.insert(ip_str);
                }
                else if (rtype == 5) {                              // CNAME
                    std::string cname;
                    int tmp = pos;
                    parse_name(tmp, cname);
                    cnames.insert(cname);
                }
                pos += rdlen;
            }

            /* ===== 5. 打印 ===== */
            std::string c_part, a_part;
            for (auto& c : cnames) c_part += c + " ";
            for (auto& a : ips)    a_part += a + " ";
            log_line("[UDP-TAP] DNS parse : %s | %s | %s",
                qname.c_str(),
                c_part.empty() ? "-" : c_part.c_str(),
                a_part.empty() ? "-" : a_part.c_str());
            };
        print_dns_line();
    }
    /* 出错或会话被删时退出 */
    closesocket(udpSock);
}


void UCB::on_packet(const Packet& pkt, HANDLE tap) {
	if (this->udpSock == INVALID_SOCKET) {
        SOCKET udp = socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = inet_addr(UDP_ADDR);
        local.sin_port = htons(0);

        if (bind(udp, (sockaddr*)&local, sizeof(local)) != 0) {
            closesocket(udp);
        }

        if (udp == INVALID_SOCKET) { return; }

		this->udpSock = udp;

        std::thread(udp_relay_to_tap, tap, this->quad, udp).detach();
	}

    /* 7. 发 UDP 报文 */
    const auto& us = this->udpSock;
    sockaddr_in to = { 0 };
    to.sin_family = AF_INET;
    to.sin_port = htons(pkt.quad.dport);
    to.sin_addr.s_addr = inet_addr("8.8.8.8");
    sendto(us, (char*)pkt.payload.data(), pkt.pay_len, 0,
        (sockaddr*)&to, sizeof(to));
}

void UCB::flush_output() {
    for (auto& p : this->send_buf) {
    }
    this->send_buf.clear();
}


