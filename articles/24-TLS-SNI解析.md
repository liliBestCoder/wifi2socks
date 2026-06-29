# 第24篇：拆开 TLS 的信封 —— SNI 解析的艺术

## 一

TLS 是加密的——但没完全加密。ClientHello 是明文的，里面写着你想访问的域名。这不是 TLS 设计者的疏忽——是必须。因为一个 IP 上托管着 100 个网站（CDN 嘛），服务器需要知道客户端在跟哪个网站说话才能选对证书。SNI（Server Name Indication）就是这个"明信片上的收件人"。

我们的 `parse_tls_sni()` 做的就是：在一堆 TLS 握手的二进制里，不依赖任何 TLS 库，纯靠指针偏移，精确地取出那个域名字符串。

## 二

TLS 1.2 ClientHello 的结构是一个套娃游戏。外层是 Record 层——ContentType（1 字节 0x16=Handshake）+ Version + Length。中层是 Handshake 层——HandshakeType（0x01=ClientHello）+ Length + ClientVersion + Random(32 字节)。内层是各种扩展——SessionID、Cipher Suites、Compression、Extensions。SNI 藏在 Extensions 里。

解析的过程就是不断的"读长度→跳过→读下一个长度→跳过→……找到了！"——直到某个 Extension 的 Type 等于 0x0000（Server Name）。然后从这个 Extension 里提取 Server Name List → Server Name Type(0x00=host_name) → Server Name Length → Server Name。

整个过程不调任何外部库，就是指针偏移 + 长度检查 + 网络字节序转换。为什么不用现成的 TLS 库？因为引入 OpenSSL 或 BoringSSL 只为解析 SNI 是杀鸡用牛刀。而且这个函数在数据包的热路径上——每个新 TCP 连接的最初几个字节里就要调一次——引入一个庞大的 TLS 库会增加几十毫秒的启动延迟和几 MB 的内存占用。

## 三

解析 SNI 的代码有一个容易被忽视的防御：**每一层都要检查长度字段是否越界。** 一个恶意构造的 ClientHello 可以在 Length 字段里填 0xFFFF——如果解析器不检查就直接跳转，结果就是读到未分配内存然后崩溃。在热路径上做安全检查看起来"浪费 CPU"，但不做的话一次恶意流量就能让你的软路由挂掉。

## 四

如果 ClientHello 被 TCP 分片了——前半截在一个包里，后半截在另一个包里——一次 `parse_tls_sni()` 调用拿不到完整数据，解析失败。解决方案是 `m_initial_buffer` 缓冲：每次新数据到达时追加到 buffer，然后尝试解析。成功了→用域名做路由决策。几百字节了还没成功→放弃嗅探，退化为 IP 路由。

这个缓冲设计让我们的系统能处理"非标准的 TCP 分段"。绝大多数实现不会分段 ClientHello——但不是所有实现都是"绝大多数"。IoT 设备、游戏服务器、嵌入式系统——它们的 TCP 栈可能在任何时刻分段。防御性编程的第一课：不要假设其他人会按你期望的方式行事。

---

*本文是《从0到1编写一个硬核软路由》系列的第二十四篇。上一篇：[第23篇：DNS的三重奏](./23-DNS的三重奏.md) | 下一篇：[第25篇：HTTP明文与网络检测请求](./25-HTTP明文与网络检测请求.md)*
