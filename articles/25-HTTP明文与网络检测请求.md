# 第25篇：HTTP 明文与那些奇怪的网络检测请求

## 一

2026 年了，还有人在用明文 HTTP。不是落后——是不需要加密。联网检测的本质就是访问一个公开的 URL 看能不能通，不涉及任何隐私。用 HTTPS 反而增加了证书校验和 TLS 握手的开销。

## 二

`parse_http_host()` 的逻辑简单到令人感动——在请求的原始字节里找到 `Host:` 头，跳过空白，读到行尾。跟 TLS SNI 解析比，这简直是饭后散步。但 Host 头可以被伪造——不过在一个透明代理的场景里，客户端不知道代理存在，伪造动机几乎为零。

## 三

真正有趣的是联网检测。你连上新 WiFi 后，每台设备都会自动访问一个特定的 URL 来测试"我能不能上网"。每个厂商访问的 URL 都不一样：

- Google/Android：`connectivitycheck.gstatic.com/generate_204`——期待 HTTP 204
- Apple：`captive.apple.com/hotspot-detect.html`——期待"Success"
- 微软：`www.msftconnecttest.com/connecttest.txt`——期待特定字符串
- 小米：`connect.rom.miui.com/generate_204`
- 华为：`connectivitycheck.platform.hicloud.com`
- OPPO：`conn-service-cn-04.allawntech.com`（用的是第三方 AllawnTech）

## 四

为什么要特殊处理这些流量？如果把检测流量也代理了——代理延迟高的时候设备会误判"这个 WiFi 需要登录"，弹出 Captive Portal 页面。用户一脸懵："我连自己的热点为什么要登录？"

所以策略是：识别→标记→直连放行。这些流量不值得走代理，而且直连的延迟最低。`DnsProbeTracker::classify()` 把这些检测域名的 DNS 查询标记出来，后续路由决策读到标记就直连。

## 五

`generate_204` 这个路径设计得很优雅。HTTP 204 的意思是"No Content"——服务器收到了请求，但没什么要返回的。Google 的服务器收到这个请求后不需要查数据库、不需要渲染页面，直接回一个 204 就行。这是极致的极简——一个完美的"你还活着吗？""活着。"的对话。

---

*本文是《从0到1编写一个硬核软路由》系列的第二十五篇。上一篇：[第24篇：TLS SNI解析](./24-TLS-SNI解析.md) | 下一篇：[第26篇：IOCP与异步I/O](./26-IOCP与异步IO.md)*
