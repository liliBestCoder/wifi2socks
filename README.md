# wifi2socks

[![License: GPL v3 with WinPkFilter Exception](https://img.shields.io/badge/License-GPLv3%20with%20Linking%20Exception-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-brightgreen.svg)]()
[![C++](https://img.shields.io/badge/Standard-C%2B%2B17-blue.svg)]()
[![Release](https://img.shields.io/github/v/release/liliBestCoder/wifi2socks?color=orange)](https://github.com/liliBestCoder/wifi2socks/releases)
[![Client: Ghost Proxifier Pro](https://img.shields.io/badge/Client-Ghost%20Proxifier%20Pro-0078D4?logo=windows&logoColor=white)](https://github.com/liliBestCoder/ghost-proxifier-pro)

> **Windows 硬件级硬核软路由与透明代理网关**  
> 基于 C++ 与 Windows NDIS Filter 驱动（WinPkFilter）从零构建，支持全透明 TCP/UDP 流量劫持、HTTP 代理转发（HTTP CONNECT 隧道）、GeoIP/GeoSite 智能分流与自带 WiFi 热点/有线网卡网关。

> [!NOTE]
> **💡 寻找 Windows 本机单应用 / 进程代理工具？**  
> 本项目（wifi2socks）专注于**局域网网关与 WiFi 热点透明软路由**（多设备零配置接入）；  
> 如果你需要让 **Windows 本机指定软件（如 Claude Desktop、Cursor、命令行开发工具或特定应用）走独立代理**，推荐使用作者的配套客户端：[**Ghost Proxifier Pro**](https://github.com/liliBestCoder/ghost-proxifier-pro) —— 原生图形界面，免装虚拟网卡与驱动、不修改系统路由表，拖入 exe 即可自动接管该进程及其所有子进程网络流量。

---

## 🌟 项目简介

在传统的软路由方案（如 OpenWrt、RouterOS、爱快等）中，用户通常需要准备软路由硬件、刷机、配置 Linux 网络栈和复杂的防火墙规则。

**wifi2socks** 旨在为 Windows 用户提供一套**开箱即用、双击即跑的硬件级软路由与透明代理系统**：
- **全透明劫持**：在网络 Layer 2（NDIS 驱动层）实时捕获并转发数据包，局域网连接设备（手机、电视、主机）无需配置任何客户端、PAC 或证书。
- **智能分流路由**：结合 V2Ray 格式离线规则库（`geoip.dat` 与 `geosite.dat`）与 TLS SNI 域名嗅探，实现毫秒级国内直连、海外代理、广告恶意域名阻断。
- **QUIC 优化与快速降级**：针对移动端 App 频繁发起 QUIC 导致握手超时或黑屏的问题，对阻断的海外 QUIC 发送 ICMP Port Unreachable，促使客户端瞬时 fallback 到 TCP。
- **高吞吐网络栈**：批量数据包读取（`ReadPackets`）、内存对象池（`PacketPool`、`ConnectionPool`）与 DNS-over-TCP 连接池加速。
- **全套网络基础设施**：内置自研轻量级 DHCP 服务器、HTTP API 监控服务器以及 WiFi AP 虚拟热点管理（同时支持有线网卡模式）。

---

## 🏗️ 系统架构图

```
                       +-----------------------------------+
                       |    局域网设备 (手机 / PC / TV)     |
                       +-----------------------------------+
                                         │
                  (WiFi AP 模式 / 有线网卡模式 Ethernet AP)
                                         ▼
+───────────────────────────────────────────────────────────────────────────+
│                              NDIS 驱动层                                   │
│                  WinPkFilter (LightWeight Filter Driver)                  │
│                [批量抓包 ReadPackets -> MSTCP 流量拦截]                   │
+───────────────────────────────────────────────────────────────────────────+
                                         │
                                         ▼
+───────────────────────────────────────────────────────────────────────────+
│                         wifi2socks 用户态核心引擎                          │
│                                                                           │
│   +────────────────────+   +─────────────────────+   +────────────────+   │
│   |    DHCP Server     |   |    HTTP API Server  |   |  WiFi AP 管理  |   │
│   | (自动分配局域网 IP)|   |  (状态监控与控制)   |   | (热点广播托管) |   │
│   +────────────────────+   +─────────────────────+   +────────────────+   │
│                                                                           │
│   +───────────────────────────────────────────────────────────────────+   │
│   |                  数据平面 Data Plane (热路径)                     |   │
│   |                                                                   |   │
│   |  1. NAT 管理与连接跟踪 (nat_manager / connection_pool)            |   │
│   |  2. DNS 代理与缓存优化 (dns_over_tcp_proxy / dns_probe_tracker)   |   │
│   |  3. 协议嗅探器 (tls_parser 提取 SNI 域名)                          |   │
│   |  4. 规则引擎 (rule_manager + GeoChecker: geoip.dat / geosite.dat) |   │
│   |  5. 代理执行器:                                                   |   │
│   |     ├── Direct (直连原路放行)                                     |   │
│   |     ├── Block  (拦截 / QUIC 发送 ICMP Port Unreachable)           |   │
│   |     └── Proxy  (通过 HTTP CONNECT 隧道转发至 Upstream)            |   │
│   +───────────────────────────────────────────────────────────────────+   │
+───────────────────────────────────────────────────────────────────────────+
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
            +───────────────+                         +───────────────+
            |  本地网络直连 |                         |  HTTP 代理源  |
            |  (国内流量)   |                         |  (海外流量)   |
            +───────────────+                         +───────────────+
```

---

## 📂 模块化目录结构

项目源码遵循清晰的分层架构组织：

```text
wifi2socks/
├── src/
│   ├── core/                  # 主程序入口与事件循环引擎
│   │   ├── wifi2socks.cpp
│   │   ├── main_dispatcher.cpp / .h
│   │   └── worker.cpp / .h
│   │
│   ├── driver/                # NDIS 内核截包与 WinPkFilter 驱动交互
│   │   ├── winpkfilter_driver.cpp / .h
│   │   ├── ndisapi.h
│   │   ├── ndisapilib.lib / ndisapidll.lib / ndisapidll.dll
│   │   └── Common.h           # 协议头与内核交互结构体
│   │
│   ├── proxy/                 # 数据平面：透明代理与连接管理
│   │   ├── proxy_tcp.cpp / .h
│   │   ├── proxy_udp.cpp / .h
│   │   ├── nat_manager.cpp / .h
│   │   ├── connection_pool.cpp / .h
│   │   ├── packet_pool.cpp / .h
│   │   └── tls_parser.cpp / .h
│   │
│   ├── rules/                 # 规则引擎与 Geo 分流
│   │   ├── rule_manager.cpp / .h
│   │   ├── geo_checker.cpp / .h
│   │   └── common.pb.cc / .h
│   │
│   ├── services/              # 嵌入式网络服务
│   │   ├── dhcp_server.cpp / .h
│   │   ├── dns_over_tcp_proxy.cpp / .h
│   │   ├── dns_cache.h
│   │   ├── dns_probe_tracker.h
│   │   ├── wifi_ap.cpp / .h
│   │   ├── wifi_ap_listener.cpp / .h
│   │   └── http_server.cpp / .h
│   │
│   └── utils/                 # 通用工具、配置与日志
│       ├── config_loader.cpp / .h
│       ├── app_config.h
│       ├── app_listener.cpp / .h
│       ├── adapter.cpp / .h
│       ├── traffic_manager.cpp / .h
│       └── logger.cpp / .h
│
├── tools/
│   └── diag_tool/             # 独立排障诊断工具
│       ├── diag_tool.cpp
│       └── diag_tool.vcxproj
│
├── articles/                  # 30+ 篇专栏技术文章
├── build.bat                  # 一键构建脚本（集成依赖还原与构建）
├── config.ini                 # 运行时配置文件
├── packages.config            # NuGet 依赖配置（protobuf-native）
├── wifi2socks.sln             # Visual Studio 解决方案
├── wifi2socks.vcxproj         # 项目工程定义文件
└── README.md
```

---

## ⚙️ 编译与构建指南

### 1. 环境准备
- **操作系统**：Windows 10 / Windows 11 (64-bit)
- **编译工具**：Visual Studio 2022（需安装 **使用 C++ 的桌面开发** 工作负荷，包含 MSVC v143 和 MSBuild）
- **包管理器**：`nuget.exe`（项目内置一键脚本 `build.bat` 会自动检测并按需下载）

### 2. 外部依赖管理
- **Protobuf C++ 运行时**：通过 NuGet 原生包 `protobuf-native (6.33.4.2)` 自动拉取与集成，无需手动编译源码或在 Git 中提交大体积二进制。
- **GeoIP / GeoSite 规则库**：`build.bat` 在首次构建时会自动从官方源（`Loyalsoldier/v2ray-rules-dat`）拉取最新 Release 资产，避免二进制数据导致 Git 仓库历史膨胀。

### 3. 一键编译（推荐）
在项目根目录下直接运行 `build.bat`：

```bat
# 默认编译 Release x64
build.bat

# 或者显式指定配置与架构
build.bat Release x64
build.bat Debug x64
```

脚本将自动执行：
1. 检测 Visual Studio 2022 编译环境（MSBuild）；
2. 还原 NuGet 原生依赖包（`protobuf-native`）；
3. 检查并按需自动下载最新 `geoip.dat` 与 `geosite.dat`；
4. 编译主程序 `wifi2socks.sln`（同时编译 `wifi2socks` 与 `diag_tool`）；
5. 自动将所需可执行程序、驱动动态库、规则库与配置文件统一部署至 `x64\Release\`。

### 4. 使用 Visual Studio IDE 编译
1. 双击打开 `wifi2socks.sln`；
2. 解决方案平台选择 **Release** 和 **x64**；
3. 右键解决方案 -> 选择 **还原 NuGet 程序包**；
4. 点击 **生成解决方案**（Ctrl + Shift + B）。

---

## 🚀 运行与使用配置

### 1. 安装 WinPkFilter 驱动
由于系统需要工作在 NDIS 驱动层截获以太网帧，运行前请确保目标机器已安装 **WinPkFilter (NDIS LightWeight Filter)** 驱动：
- 官方下载：[NT Kernel Resources WinPkFilter](https://www.ntkernel.com/winpkfilter/)
- 确保系统服务中驱动正常加载。可通过配套运行 `diag_tool.exe` 验证驱动可用状态。

### 2. 配置文件说明 (`config.ini`)
在程序同级目录下放置 `config.ini`：

```ini
[Common]
# 软路由自身作为网关的 IP
gateway_ip = 192.168.102.1

# 上游 HTTP 代理服务器地址与端口（支持 HTTP CONNECT 隧道的代理端，如 Clash/V2Ray/Xray 的 mixed-port 或 http-port）
upstream_ip = 127.0.0.1
upstream_port = 2080

# 代理与直连 DNS 目标
proxy_dns_server = 8.8.8.8
direct_dns_server = 223.5.5.5

# 监控与控制 API 端口
http_api_port = 8080

# 虚拟 WiFi 热点配置
wifi_ssid = wifi2socks_ap
wifi_password = password123
log_level = info

# 服务端先发包端口加速白名单（SSH、MySQL、Redis等）
server_first_eager_ports = 22, 8022, 3306, 63306

[Rules]
# 强制直连的 IP / 域名
direct_ip_list = 192.168.1.100, 150.109.29.169
direct_domain_list = qq.com, sina.com

# 拦截列表
block_ip_list = 1.2.3.4
block_domain_list = 

# 强制代理的 IP / 域名
proxy_ip_list = 
proxy_domain_list = github.com, google.cn
```

### 3. 工作模式切换
wifi2socks 支持两种网关模式：
1. **WiFi AP 模式（默认）**：自动开启 Windows 虚拟热点，移动设备直接搜索连接该 SSID；
2. **有线网卡模式（Wired AP）**：将电脑多余的以太网网口作为 LAN 口，外接交换机或其他设备。
   - 切换方式：在环境变量中设置 `WIFI2SOCKS_MODE=wired` 或在配置项指定。

### 4. 启动程序
请以**管理员权限**运行控制台或可执行文件：
```powershell
.\x64\Release\wifi2socks.exe
```

---

## 🛠️ 排障与诊断工具 (`diag_tool.exe`)

当遇到网卡未识别、WiFi 无法启动、驱动未载入时，运行：
```powershell
.\x64\Release\diag_tool.exe
```
工具将输出详细的自检报告：
- WinPkFilter 设备状态与驱动可用性检测；
- 本机适配器与虚拟无线热点接口探测；
- DHCP 冲突排查与系统事件日志（Event Trace）分析。

---

## 📚 教程与技术文档

项目 `articles/` 目录下收录了完整的 **33 篇硬核实战专栏文章**，从以太网数据帧结构、NDIS 驱动内核交互、手写轻量级 TCP 状态机、TLS SNI 解析到高并发连接池与软路由调优，欢迎阅读与交流！

---

## 🔗 相关项目与生态

- 🌟 **[Ghost Proxifier Pro](https://github.com/liliBestCoder/ghost-proxifier-pro)**：Windows 原生进程级透明代理工具，完整支持 TCP/UDP 双协议转发。免驱动/虚拟网卡、不改路由表，支持拖拽程序及子进程全自动追踪接管。
- 📊 **[Ghost Proxifier Monitor](https://github.com/liliBestCoder/ghost-proxifier-monitor)**：Ghost Proxifier Pro 客户端配套的实时数据监控大屏与活跃分析后台。

---

## 📄 开源许可证

本项目核心源码基于 **[GNU General Public License v3.0 (GPL-3.0)](LICENSE)** 协议开源，并附加针对 **WinPkFilter (NT KERNEL)** 驱动库的 **Linking Exception**（链接豁免条款）。

- **代码自由与防商业套壳**：基于 GPLv3，任何基于本项目修改、二次分发或集成的衍生程序，必须以同等开源许可证公开其源码；
- **驱动库链接豁免**：根据 GPLv3 第 7 条授权，允许本项目与 WinPkFilter（`ndisapi.h`, `ndisapidll.dll`, `ndisapilib.lib` 等 NT KERNEL 专有 SDK 库）链接并分发二进制程序。
