<!-- LOGO -->
<p align="center">
  <img src="app_icon.ico" alt="Logo" width="64">
</p>

<h1 align="center">Ghost Proxifier</h1>

<p align="center">
  进程级透明代理工具 — 通过 DLL 注入 Hook Winsock API，将目标进程的所有网络流量透明转发到 HTTP 代理。
  <br/>
  无需修改路由表，无需指定路由规则。
</p>

<p align="center">
  <a href="#背景">背景</a>
  ·
  <a href="https://github.com/liliBestCoder/ghost-proxifier/releases" target="_blank">下载</a>
  ·
  <a href="#构建">构建</a>
  ·
  <a href="#使用">基本用法</a>
</p>

<p align="center">
  🚀 <a href="https://ghostproxifier.com/" target="_blank"><b>Ghost Proxifier Pro</b></a> — 带现代化 UI、进程规则管理、流量面板等高级功能
</p>

---

## 背景

日常开发中，经常需要同时使用**科学上网代理**和**公司 VPN** 访问不同的网络资源。比如：

- 使用 **Clash Meta** 的 TUN 模式跑 Antigravity 等 AI 编程工具
- 使用公司 VPN 访问内网资源、提交代码

两个 VPN 同时运行时，**路由表经常冲突** — 必须手动在 Clash Meta 里配置路由规则排除公司内网的 IP 段。这样做不仅繁琐，而且不稳定，偶尔公司 VPN 的连接还会莫名断开。

Ghost Proxifier 换了一个思路：**不用 TUN，不动路由表**。只需要把 Clash Meta 开一个 HTTP 入站端口，Ghost Proxifier 针对需要走代理的进程单独注入，其他进程和公司 VPN 完全不受影响。

## 为什么需要 Ghost Proxifier

现有的代理方案各有痛点：

- **系统代理 / PAC** — 依赖应用主动读取代理设置，很多程序不遵守，流量直接泄露
- **VPN / TUN 全局代理** — TUN 网卡内核态与用户态频繁切换，处理慢且连接容易断；多个 VPN 同时使用时路由表冲突，流量走向不可控

Ghost Proxifier 直接 Hook 目标进程的网络函数，在 **Winsock API 层** 拦截所有连接，做到：

- **对应用完全透明** — 无需应用支持代理，任何使用 Winsock 的程序都能代理
- **基于 HTTP 代理** — 兼容主流代理软件（V2Ray、Clash、NekoBox 等均支持 HTTP 入站）
- **进程粒度控制** — 只代理指定进程，不影响系统其他流量，与公司 VPN 和平共存
- **自建 DNS 解析** — 防止 DNS 泄露和 DNS 污染，确保域名解析的纯净性

## 整体架构

```
                          Ghost Proxifier 架构
┌─────────────────────────────────────────────────────────────┐
│                      目标进程 (e.g. Chrome)                  │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ DNS 请求     │  │ TCP 连接      │  │ 数据发送           │  │
│  │ getaddrinfo  │  │ connect()    │  │ send() / WSASend() │  │
│  │ GetAddrInfoW │  │ ConnectEx()  │  │                    │  │
│  │ sendto(53)   │  │ WSAConnect() │  │                    │  │
│  └──────┬───────┘  └──────┬───────┘  └─────────┬──────────┘  │
│         │ HOOK             │ HOOK               │ HOOK        │
├─────────┼─────────────────┼─────────────────────┼────────────┤
│         ▼                 ▼                     ▼            │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ Local DNS   │  │ 重定向到代理  │  │ Lazy Handshake     │  │
│  │ Proxy       │  │ 保存目标信息  │  │                    │  │
│  │             │  │ 到 Pending   │  │ 1. 检查 PendingMap │  │
│  │ UDP → TCP   │  │ Map          │  │ 2. HTTP CONNECT    │  │
│  │ 转发到      │  │              │  │ 3. 发送原始数据    │  │
│  │ 8.8.8.8:53  │  │ 非阻塞返回   │  │                    │  │
│  └──────┬───────┘  └──────┬───────┘  └─────────┬──────────┘  │
│         │                 │                     │            │
│         │    ghost_core.dll (注入到目标进程)      │            │
└─────────┼─────────────────┼─────────────────────┼────────────┘
          │                 │                     │
          ▼                 ▼                     ▼
   ┌─────────────────────────────────────────────────────┐
   │              上游 HTTP CONNECT 代理                  │
   │          (V2Ray / Clash / NekoBox / ...)             │
   │                 127.0.0.1:2080                       │
   │                                                     │
   │  ┌──────────┐  ┌────────────────────────────────┐   │
   │  │ DNS 查询  │  │ CONNECT www.google.com:443     │   │
   │  │ TCP 53   │  │                                │   │
   │  │ → 8.8.8.8│  │ → 建立隧道 → 转发加密流量      │   │
   │  └──────────┘  └────────────────────────────────┘   │
   └─────────────────────────────────────────────────────┘
```

## 核心机制

### 1. HTTP 代理协议

Ghost Proxifier 使用 **HTTP CONNECT** 方法与上游代理通信。这是一个广泛支持的标准隧道协议：

```
# 反查到域名时（优先）
客户端 → 代理:  CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n

# 反查不到域名时（fallback）
客户端 → 代理:  CONNECT 142.251.45.10:443 HTTP/1.1\r\nHost: 142.251.45.10:443\r\n\r\n

代理 → 客户端:  HTTP/1.1 200 Connection Established\r\n\r\n
                （此后代理变为透明隧道，双向转发原始数据）
```

在 Hook 场景下，`connect()` 拿到的是 **IP 地址**而非域名。Ghost Proxifier 通过 DNS 解析时建立的 `IP → 域名` 映射表进行反查，**优先使用域名**发送 CONNECT 请求，让上游代理能基于域名做精确分流。

当反查不到域名时（如注入前已缓存的 DNS），则回退为使用 IP 发送 CONNECT，此时上游代理只能依赖 **GeoIP 规则** 判断流量走向。如果 DNS 被污染返回了错误的 IP，GeoIP 判定也会跟着出错（例如国内域名被污染为海外 IP，导致不必要地走代理）。这正是 **Local DNS 防污染**至关重要的原因 — 确保拿到真实 IP，无论走域名还是 GeoIP 分流都能得到正确结果。

### 2. 延迟握手（Lazy Handshake）

传统做法在 `connect()` 时同步完成代理连接 + HTTP CONNECT 握手，会阻塞应用的 IO 线程。Chrome 等现代浏览器使用非阻塞 IO，被阻塞后会认为进程卡死并重启。

Ghost Proxifier 的解决方案：

| 阶段 | 操作 | 阻塞？ |
|------|------|--------|
| `connect()` | 重定向到代理地址，保存目标信息到 PendingMap | ❌ 非阻塞 |
| 等待连接 | 应用事件循环正常运行 | ❌ |
| `send()` 首次调用 | 从 PendingMap 取出目标信息，完成 HTTP CONNECT | ✅ 短暂阻塞（< 5ms） |
| 后续 `send()` | 直接转发 | ❌ |

### 3. 自建 Local DNS

**为什么不用系统 DNS：**
- **DNS 泄露** — 系统 DNS 直接发给 ISP，暴露访问意图
- **DNS 污染** — 部分地区 ISP 返回虚假 IP（如 GFW 投毒），导致无法连接真实服务器

**Ghost Proxifier 的 DNS 方案：**

```
应用 DNS 请求 (UDP)
    ↓ Hook 拦截
Local DNS Proxy (127.0.0.1:随机端口)
    ↓ UDP → TCP 转换
通过上游代理建立 CONNECT 隧道到 8.8.8.8:53
    ↓ TCP DNS 查询
Google DNS 返回真实结果
    ↓ 记录 IP→域名 映射（供 connect 时反查）
返回给应用
```

同时记录 `IP → 域名` 映射表，使得 `connect(IP)` 时能反查到域名，让上游代理收到的是 `CONNECT domain:port` 而非纯 IP，确保 GeoIP 分流规则正常工作。

### 4. DoH（DNS-over-HTTPS）阻断

Chrome 等浏览器会尝试使用 DNS-over-HTTPS（DoH），直接通过 HTTPS 查询 DNS，绕过我们的 Local DNS Proxy。

Ghost Proxifier 通过识别已知 DoH 服务器 IP（如 `8.8.8.8:443`、`1.1.1.1:443`）并在 `connect()` 阶段直接返回 `WSAECONNREFUSED`，强制浏览器回退到标准 DNS，确保所有 DNS 查询都走 Local DNS Proxy。

```
Chrome → connect(8.8.8.8:443)  → DoH 请求
                ↓ Hook 识别为 DoH 服务器
            返回 WSAECONNREFUSED
                ↓ Chrome 回退
Chrome → sendto(8.8.8.8:53)   → 标准 DNS → 被 Local DNS Proxy 接管 ✅
```

## 构建

由于项目依赖 MinHook 子模块，克隆时请加上 `--recursive` 参数：

```cmd
git clone --recursive https://github.com/liliBestCoder/ghost-proxifier.git
cd ghost-proxifier
```

**依赖：**
- Windows 10+
- Visual Studio 2022（含 C++ 桌面开发工具）
- CMake 3.15+

```cmd
compile.bat
```

产物输出到 `bin/` 目录：
- `ghost-proxifier.exe` — CLI 管理工具 (x64)
- `ghost_core_x64.dll` / `ghost_core_x86.dll` — 注入到目标进程的 Hook DLL
- `ghost_launcher_x64.exe` / `ghost_launcher_x86.exe` — 注入辅助工具
- `ghost_dns_dump.exe` — DNS 诊断工具

## 使用

### 基本用法

```cmd
# 等待进程启动后立即注入（推荐：无旧连接、无 QUIC 缓存问题）
ghost-proxifier inject chrome.exe

# 注入已有进程
ghost-proxifier inject 1234

# 注入进程及其所有子进程
ghost-proxifier inject --tree chrome.exe

# 卸载 DLL
ghost-proxifier eject 1234
```

### 配置管理

```cmd
# 查看当前配置
ghost-proxifier config show

# 添加上游代理节点
ghost-proxifier config upstream add myproxy 127.0.0.1:1080

# 切换活跃节点
ghost-proxifier config upstream use myproxy

# 删除节点
ghost-proxifier config upstream rm myproxy

# 设置 DNS 服务器
ghost-proxifier config dns 1.1.1.1
```

### 完整命令

| 命令 | 说明 |
|------|------|
| `list` | 列出所有进程及代理状态 |
| `inject <name>` | 等待进程启动，瞬间注入（干净启动，无旧连接） |
| `inject <pid>` | 注入已有进程 |
| `inject --tree <name>` | 等待进程启动，同时注入所有子进程 |
| `eject <pid>` | 从进程卸载 ghost_core.dll |
| `status` | 显示全局代理状态和流量统计 |
| `config show` | 显示当前配置 |
| `config upstream add <name> <addr>` | 添加上游代理节点 |
| `config upstream rm <name>` | 删除上游代理节点 |
| `config upstream use <name>` | 切换活跃上游节点 |
| `config dns <server>` | 设置 DNS 服务器 |
| `monitor` | 实时流量监控 (Ctrl+C 退出) |

### 日志示例

```
[14:08:09] [Init] Hooks installed successfully (PID: 3188)
[14:08:19] [DNS-Proxy] GetAddrInfoW: play.googleapis.com -> [216.239.32.223] (1 IPs)
[14:08:19] [hook] ConnectEx: 216.239.32.223:443 | play.googleapis.com
[14:08:19] [Proxy] Handshake OK: 216.239.32.223:443 | play.googleapis.com
[14:10:06] [DNS] Query: www.googleapis.com. -> A: [142.250.72.234, 142.251.45.10]
[14:10:06] [DNS] Query: www.googleapis.com. -> AAAA: [2607:f8b0:4004:800::200e]
```

## 实战示例

### 代理 Chrome 浏览器

```cmd
# 1. 先运行此命令，等待 Chrome 启动
ghost-proxifier inject chrome.exe
# 输出: Watching for chrome.exe... (new instances will be injected immediately)

# 2. 再打开 Chrome，插件立即注入
# 输出: New process detected: PID 12345 — injecting...
```

所有标签页流量自动走代理。谷歌搜索、Gmail、YouTube 均可正常访问。

### 代理 Antigravity AI 编程助手

```cmd
ghost-proxifier inject language_server_windows_x64.exe
```

然后重启 Antigravity。AI 对话、代码补全等请求通过代理转发，无需配置 TUN 或系统代理。

## 已测试应用

| 应用 | 状态 | 备注 |
|------|------|------|
| Antigravity (AI 编程) | ✅ | 注入 `language_server_windows_x64` 进程 |
| Chrome | ✅ | 注入 Network Service 进程，建议关闭安全 DNS |
| Telegram Desktop | ✅ | |

## Hook 函数列表

| 函数 | 用途 |
|------|------|
| `connect` / `WSAConnect` / `ConnectEx` | TCP 连接重定向到代理，ConnectEx 主动 Hook（防止缓存指针绕过） |
| `send` / `WSASend` | 首次发送前完成 HTTP CONNECT 握手；关闭非代理 TCP socket 强制重连 |
| `recv` / `WSARecv` | 拦截非代理 socket 的接收，强制应用通过代理重连 |
| `sendto` / `WSASendTo` | DNS UDP 53 重定向到 Local DNS Proxy；QUIC UDP 443 阻断 + 关闭 socket |
| `recvfrom` / `WSARecvFrom` | DNS 响应拦截、IP-域名映射、DNS 来源地址伪装 |
| `getaddrinfo` / `GetAddrInfoW` / `gethostbyname` | DNS 域名解析走代理 DNS-over-TCP |
| `GetAddrInfoExW` / `DnsQuery_W` / `DnsQuery_A` / `DnsQueryEx` | 异步 DNS API 拦截（Windows 8+、Chromium、Cygwin） |
| `closesocket` | 清理 PendingMap 和代理完成状态 |
| `WSAIoctl` | ConnectEx 延迟 Hook（兜底） |
| `DoH 阻断` | 识别已知 DoH 服务器 IP（8.8.8.8:443 等），返回拒绝强制回退标准 DNS |
| `QUIC 阻断` | UDP 443 send/sendto/recv 全路径阻断，返回 `WSAENETUNREACH` 触发 TCP 回退 |

## License

MIT
