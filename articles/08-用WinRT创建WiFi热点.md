# 第8篇：用 WinRT 创建 WiFi 热点 —— 微软给你挖的坑

## 一

Windows 上的 API，按让人痛苦的程度分三种。第一种是 Win32 API，又老又啰嗦但至少文档齐全，你总能找到答案。第二种是 COM，引用计数和 HRESULT 让每个人刚接触时都头疼，但搞懂了之后你会发现它其实是个逻辑自洽的体系。

第三种是 WinRT。微软在 Windows 8 时代推出的"下一代 API"，理念是统一的异步编程模型、跨语言投影、现代化的接口设计。理念很好。问题是——**WinRT 在 C++ 中的调用复杂度超出了人类大脑的舒适范围。** 你需要同时理解 COM 接口、模板元编程（`ComPtr`）、异步操作（`IAsyncOperation<T>`）、事件令牌（`EventRegistrationToken`）、以及字符串互操作（`HSTRING` vs `std::wstring` vs `Platform::String`）。

但没办法。Windows 上创建 WiFi Direct 热点的唯一官方 API，就是 WinRT 的 `Windows.Devices.WiFiDirect` 命名空间。要么用 WinRT，要么别做热点。

## 二

WiFi Direct 和传统热点（SoftAP）是两回事，但很多人（包括以前的我）把它们混为一谈。

WiFi Direct 是一对一的点对点连接协议。两台支持 WiFi Direct 的设备可以直接连接，不需要 AP。你传文件给同事，手机投屏到电视——这是 WiFi Direct 的设计场景。

WiFi Direct Legacy AP 才是我们需要的"热点"。它是 WiFi Direct 的一个扩展：一台设备充当传统 AP，广播 SSID，任何支持 WiFi 的设备（不管支不支持 WiFi Direct）都能连接。关键配置在 `WiFiDirectLegacySettings` 对象里——`IsEnabled` 必须显式设为 `true`。忘了这行，设备就以纯 WiFi Direct 模式广播——大多数手机根本搜不到这个"热点"。

## 三

创建热点的代码流程是三层嵌套的俄罗斯套娃：Publisher → Advertisement → LegacySettings。每一层都是一个 `ComPtr<T>`，返回值要检查 HRESULT。SSID 和密码通过 `LegacySettings` 设置。

密码设置还多绕一层——不能直接传字符串，要包装成 `PasswordCredential` 对象。这是 WinRT 安全模型的要求，目的是防止密码以明文形式在内存里到处乱跑。理论上是对的，但在调试的时候，你每次改密码都要多写三行模板代码，非常烦躁。

`Start()` 是异步操作，调用后 WiFi 芯片需要几秒钟配置信道。在这几秒内，设备搜不到热点——不是热点没启，是芯片在忙。很多开发者在这里犯了个错：调了 `Start()` 立刻去搜 SSID，搜不到就以为出错了。

## 四

热点不是一劳永逸的。Windows 有一个节能策略：如果约两分钟没有任何设备活动，自动关闭热点广播。这是为了省电——但软路由的场景里，你可能晚上睡觉了手机自动断 WiFi，第二天早上热点没了。

解决方案是一个凌晨三点想到的 trick：每 30 秒向所有 DHCP 客户端发一个 UDP 包到端口 9（discard 协议）。端口 9 是 RFC 863 定义的——收到数据后直接丢弃。任何副作用都没有。但这个包足以让 Windows 认为"有网络活动"，重置那个两分钟的倒计时。

这就像你每隔一段时间去拍拍路由器说"嘿，还活着吗？"——路由器根本不需要回答，你拍的这一下就够了。

## 五

最后聊一件事：WiFi Direct 热点有时候就是启动不了。`Start()` 返回了，Event Log 里一句"Operation aborted"。谁 abort 的？为什么？文档没说。

依照血的教训，常见原因包括：WiFi 开关没开（Windows 不会告诉你，它只说"aborted"）、网卡不支持 WiFi Direct（某些老网卡或驱动程序不完整）、Windows 自带的"移动热点"功能正在占用 WiFi Direct 资源、5GHz 频段在部分国家需要先做雷达检测（DFS）。

如果这些都排除了还是不行——试一下有线模式。网线永远不跟你耍脾气。

---

*本文是《从0到1编写一个硬核软路由》系列的第八篇。上一篇：[第7篇：ARP的谎言与DHCP的魔法](./07-ARP的谎言与DHCP的魔法.md) | 下一篇：[第9篇：密码、连接与KeepAlive](./09-密码连接与KeepAlive.md)*
