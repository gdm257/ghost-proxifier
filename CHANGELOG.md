# Changelog

## v0.2.0

1. 延迟握手（Lazy Handshake）：connect() 非阻塞重定向到代理，首次 send() 时完成 HTTP CONNECT，不阻塞应用 IO 线程

2. 自建 Local DNS：Hook 全部 DNS API，通过代理 TCP 隧道到 8.8.8.8 解析，IP→域名反查确保上游代理精确分流

3. DoH / QUIC 阻断：UDP 443 全路径拦截 + closesocket + WSAENETUNREACH，强制 Chrome/Edge 回退 TCP

4. 非代理 Socket 强制关闭：send/recv 检测到注入前的旧 TCP 连接时自动关闭，触发应用重连走代理

5. ConnectEx 主动 Hook：DLL 初始化时预先解析并 Hook ConnectEx 函数指针，防止应用缓存指针绕过

6. DNS Hook 全覆盖：getaddrinfo、GetAddrInfoW、GetAddrInfoExW、gethostbyname、DnsQuery_W、DnsQuery_A、DnsQueryEx（Windows 8+ / Chromium / Cygwin / Edge）

7. CLI 管理工具：list / inject / eject / status / config / monitor 完整命令集

8. Watch 模式注入：等待进程启动后瞬间注入，无旧连接无 QUIC 缓存，默认行为

9. 子进程树注入：--tree 递归注入所有子进程

10. 上游代理节点管理：config upstream add/rm/use 多节点切换

11. UDP 实时日志：DLL 通过 UDP 推送日志到 CLI，彩色 TAG 渲染（DNS/Proxy/Error/Init）

12. Live Stats：每 2 秒上报 upload/download/并发连接数/延迟，monitor 命令反闪烁实时渲染

13. 模块化架构：core/ 目录 14 个文件，按职责拆分（hooks_socket / hooks_dns / proxy / dns / dns_cache / config / utils）

14. CMake 构建系统：一键 compile.bat，x64/x86 双架构，产物统一输出到 bin/

15. 已测试：Chrome ✅ / Edge ✅ / Antigravity ✅ / Telegram ✅
