<!-- LOGO -->
<p align="center">
  <img src="app_icon.ico" alt="Logo" width="64">
</p>

<h1 align="center">Ghost Proxifier</h1>

<p align="center">
  <a href="README.md">🇨🇳 中文</a>
  &nbsp;·
  <a href="https://github.com/liliBestCoder/ghost-proxifier/releases" target="_blank">Download</a>
</p>

<p align="center">
  <a href="#background">Background</a>
  ·
  <a href="#why-ghost-proxifier">Why</a>
  ·
  <a href="#architecture">Architecture</a>
  ·
  <a href="#core-mechanisms">Core</a>
  ·
  <a href="#building">Building</a>
  ·
  <a href="#usage">Usage</a>
  ·
  <a href="#command-reference">Commands</a>
</p>

<p align="center">
  Process-level transparent proxy — Hook Winsock API via DLL injection to transparently forward all network traffic from a target process through an HTTP proxy. No route table changes, no routing rules.
</p>

<p align="center">
  🚀 <a href="https://ghostproxifier.com/" target="_blank"><b>Ghost Proxifier Pro</b></a> — Modern UI, process rules, traffic panel, and more
</p>

---

## Background

In daily development, you often need both a **proxy for accessing external resources** and a **corporate VPN** simultaneously. For example:

- Using **Clash Meta** TUN mode to run AI coding tools like Antigravity
- Using a corporate VPN to access internal resources and push code

When both VPNs run at the same time, **routing tables frequently conflict** — you have to manually configure Clash Meta routing rules to exclude corporate IP ranges. This is tedious, unstable, and occasionally causes the corporate VPN connection to drop.

Ghost Proxifier takes a different approach: **no TUN, no route table changes**. Simply configure Clash Meta with an HTTP inbound port, and Ghost Proxifier injects only into processes that need to go through the proxy. Other processes and the corporate VPN remain completely unaffected.

## Why Ghost Proxifier

Existing proxy solutions have their pain points:

- **System Proxy / PAC** — Relies on applications to read proxy settings. Many programs don't comply, leaking traffic.
- **VPN / TUN Global Proxy** — Frequent context switches between kernel and user mode make it slow and unstable. Running multiple VPNs causes routing table conflicts and unpredictable traffic routing.

Ghost Proxifier hooks network functions directly in the target process at the **Winsock API layer**, intercepting all connections:

- **Completely transparent to the application** — No proxy support needed. Any Winsock-based program works.
- **HTTP proxy based** — Compatible with all major proxy tools (V2Ray, Clash, NekoBox all support HTTP inbound).
- **Process-level control** — Only proxies specified processes; coexists peacefully with corporate VPNs.
- **Built-in DNS resolver** — Prevents DNS leaks and DNS poisoning, ensuring clean domain resolution.

## Architecture

<pre>
                          Ghost Proxifier Architecture
┌─────────────────────────────────────────────────────────────┐
│                      Target Process (e.g. Chrome)           │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ DNS Request   │  │ TCP Connect   │  │ Data Send          │  │
│  │ getaddrinfo  │  │ connect()    │  │ send() / WSASend() │  │
│  │ GetAddrInfoW │  │ ConnectEx()  │  │                    │  │
│  │ sendto(53)   │  │ WSAConnect() │  │                    │  │
│  └──────┬───────┘  └──────┬───────┘  └─────────┬──────────┘  │
│         │ HOOK             │ HOOK               │ HOOK        │
├─────────┼─────────────────┼─────────────────────┼────────────┤
│         ▼                 ▼                     ▼            │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ Local DNS   │  │ Redirect to   │  │ Lazy Handshake     │  │
│  │ Proxy       │  │ proxy; save   │  │                    │  │
│  │             │  │ target info   │  │ 1. Check PendingMap│  │
│  │ UDP → TCP   │  │ to Pending    │  │ 2. HTTP CONNECT    │  │
│  │ forward to  │  │ Map           │  │ 3. Send orig data  │  │
│  │ 8.8.8.8:53  │  │               │  │                    │  │
│  │             │  │ Non-blocking   │  │                    │  │
│  └──────┬───────┘  └──────┬───────┘  └─────────┬──────────┘  │
│         │                 │                     │            │
│         │   ghost_core.dll (injected into target process)    │
└─────────┼─────────────────┼─────────────────────┼────────────┘
          │                 │                     │
          ▼                 ▼                     ▼
   ┌─────────────────────────────────────────────────────┐
   │              Upstream HTTP CONNECT Proxy            │
   │          (V2Ray / Clash / NekoBox / ...)            │
   │                 127.0.0.1:2080                       │
   │                                                     │
   │  ┌──────────┐  ┌────────────────────────────────┐   │
   │  │ DNS Query │  │ CONNECT www.google.com:443    │   │
   │  │ TCP 53    │  │                               │   │
   │  │ → 8.8.8.8 │  │ → Establish tunnel → Forward  │   │
   │  └──────────┘  └────────────────────────────────┘   │
   └─────────────────────────────────────────────────────┘
</pre>

## Core Mechanisms

### 1. HTTP CONNECT Protocol

Ghost Proxifier uses the **HTTP CONNECT** method to communicate with the upstream proxy:

<pre>
# When domain can be reverse-looked-up (preferred)
Client → Proxy:  CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n

# When domain lookup fails (fallback)
Client → Proxy:  CONNECT 142.251.45.10:443 HTTP/1.1\r\nHost: 142.251.45.10:443\r\n\r\n

Proxy → Client:  HTTP/1.1 200 Connection Established\r\n\r\n
                 (proxy becomes a transparent tunnel, bidirectionally forwarding raw data)
</pre>

In hook scenarios, `connect()` receives an **IP address** rather than a domain. Ghost Proxifier builds an `IP → Domain` mapping table during DNS resolution for reverse lookup, **preferring domain names** in CONNECT requests so the upstream proxy can make precise routing decisions.

When reverse lookup fails, it falls back to using IP in CONNECT — at which point the upstream proxy can only rely on **GeoIP rules**. This is why **Local DNS anti-poisoning** is critical.

### 2. Lazy Handshake

The traditional approach completes the proxy connection + HTTP CONNECT handshake synchronously inside `connect()`, blocking the application's IO thread. Modern browsers like Chrome use non-blocking IO and will detect the blocked thread as a hang, restarting the process.

Ghost Proxifier's solution:

| Stage | Action | Blocking? |
|------|------|--------|
| `connect()` | Redirect to proxy address, save target info to PendingMap | ❌ Non-blocking |
| Waiting | Application event loop runs normally | ❌ |
| First `send()` | Retrieve target from PendingMap, complete HTTP CONNECT | ✅ Brief (< 5ms) |
| Subsequent `send()` | Forward directly | ❌ |

### 3. Built-in Local DNS

**Why not use the system DNS:**
- **DNS Leak** — System DNS goes directly to your ISP, exposing browsing intent.
- **DNS Poisoning** — Some ISPs return fake IPs (e.g., GFW poisoning), making the real server unreachable.

**Ghost Proxifier's DNS approach:**

<pre>
App DNS Request (UDP)
    ↓ Hook intercepts
Local DNS Proxy (127.0.0.1:random port)
    ↓ UDP → TCP conversion
CONNECT tunnel to 8.8.8.8:53 via upstream proxy
    ↓ TCP DNS query
Google DNS returns real result
    ↓ Record IP→Domain mapping (for reverse lookup on connect)
Return to application
</pre>

### 4. DoH (DNS-over-HTTPS) Blocking

Browsers like Chrome attempt DNS-over-HTTPS (DoH), querying DNS directly over HTTPS, bypassing the Local DNS Proxy.

Ghost Proxifier identifies known DoH server IPs (e.g., `8.8.8.8:443`, `1.1.1.1:443`) and returns `WSAECONNREFUSED` during `connect()`, forcing the browser to fall back to standard DNS.

<pre>
Chrome → connect(8.8.8.8:443)  → DoH request
                ↓ Hook recognizes as DoH server
             Returns WSAECONNREFUSED
                ↓ Chrome falls back
Chrome → sendto(8.8.8.8:53)   → Standard DNS → Intercepted by Local DNS Proxy ✅
</pre>

## Building

The project depends on the MinHook submodule — use `--recursive` when cloning:

```cmd
git clone --recursive https://github.com/liliBestCoder/ghost-proxifier.git
cd ghost-proxifier
```

**Dependencies:**
- Windows 10+
- Visual Studio 2022 (with C++ desktop development tools)
- CMake 3.15+

```cmd
compile.bat
```

Output in `bin/`:
- `ghost-proxifier.exe` — CLI management tool (x64)
- `ghost_core_x64.dll` / `ghost_core_x86.dll` — Hook DLL injected into target processes
- `ghost_launcher_x64.exe` / `ghost_launcher_x86.exe` — Injection helper
- `ghost_dns_dump.exe` — DNS diagnostic tool

## Usage

### Basic Usage

```cmd
# Wait for a process to launch, then inject immediately (recommended: clean start)
ghost-proxifier inject chrome.exe

# Inject into an existing process
ghost-proxifier inject 1234

# Inject into a process and all its children
ghost-proxifier inject --tree chrome.exe

# Unload DLL
ghost-proxifier eject 1234
```

### Configuration

```cmd
# Show current config
ghost-proxifier config show

# Add an upstream proxy node
ghost-proxifier config upstream add myproxy 127.0.0.1:1080

# Switch active node
ghost-proxifier config upstream use myproxy

# Remove a node
ghost-proxifier config upstream rm myproxy

# Set DNS server
ghost-proxifier config dns 1.1.1.1
```

### Command Reference

| Command | Description |
|------|------|
| `list` | List all processes and their proxy status |
| `inject <name>` | Wait for process launch, inject instantly (clean start) |
| `inject <pid>` | Inject into an existing process |
| `inject --tree <name>` | Wait for process launch, inject into all child processes as well |
| `eject <pid>` | Unload ghost_core.dll from the process |
| `status` | Show global proxy status and traffic statistics |
| `config show` | Show current configuration |
| `config upstream add <name> <addr>` | Add an upstream proxy node |
| `config upstream rm <name>` | Remove an upstream proxy node |
| `config upstream use <name>` | Switch active upstream node |
| `config dns <server>` | Set DNS server |
| `monitor` | Real-time traffic monitor (Ctrl+C to exit) |

### Example Log Output

<pre>
[14:08:09] [Init] Hooks installed successfully (PID: 3188)
[14:08:19] [DNS-Proxy] GetAddrInfoW: play.googleapis.com -> [216.239.32.223] (1 IPs)
[14:08:19] [hook] ConnectEx: 216.239.32.223:443 | play.googleapis.com
[14:08:19] [Proxy] Handshake OK: 216.239.32.223:443 | play.googleapis.com
[14:10:06] [DNS] Query: www.googleapis.com. -> A: [142.250.72.234, 142.251.45.10]
[14:10:06] [DNS] Query: www.googleapis.com. -> AAAA: [2607:f8b0:4004:800::200e]
</pre>

## Real-World Examples

### Proxying Chrome

```cmd
# 1. Run this first — waits for Chrome to launch
ghost-proxifier inject chrome.exe
# Output: Watching for chrome.exe... (new instances will be injected immediately)

# 2. Then open Chrome — the DLL injects instantly
# Output: New process detected: PID 12345 — injecting...
```

All tab traffic automatically goes through the proxy. Google Search, Gmail, YouTube all work.

### Proxying Antigravity AI Coding Assistant

```cmd
ghost-proxifier inject language_server_windows_x64.exe
```

Then restart Antigravity. AI conversations, code completions, etc. are forwarded through the proxy — no TUN or system proxy configuration needed.

## Tested Applications

| Application | Status | Notes |
|------|------|------|
| Antigravity (AI Coding) | ✅ | Inject into `language_server_windows_x64` |
| Chrome | ✅ | Inject Network Service process; consider disabling Secure DNS |
| Telegram Desktop | ✅ | |

## Hooked Functions

| Function | Purpose |
|------|------|
| `connect` / `WSAConnect` / `ConnectEx` | Redirect TCP connections to proxy; proactive ConnectEx hook |
| `send` / `WSASend` | Complete HTTP CONNECT handshake before first send; close non-proxy sockets |
| `recv` / `WSARecv` | Intercept non-proxy socket receives, force reconnect through proxy |
| `sendto` / `WSASendTo` | Redirect DNS UDP 53 to Local DNS Proxy; block QUIC UDP 443 |
| `recvfrom` / `WSARecvFrom` | DNS response interception, IP-domain mapping, DNS source address spoofing |
| `getaddrinfo` / `GetAddrInfoW` / `gethostbyname` | Route DNS resolution through proxy DNS-over-TCP |
| `GetAddrInfoExW` / `DnsQuery_W` / `DnsQuery_A` / `DnsQueryEx` | Intercept async DNS APIs (Windows 8+, Chromium, Cygwin) |
| `closesocket` | Clean up PendingMap and proxy-completion state |
| `WSAIoctl` | Delayed ConnectEx hook (safety net) |
| DoH Block | Identify known DoH server IPs, return refused to force standard DNS fallback |
| QUIC Block | Full-path UDP 443 blocking, return `WSAENETUNREACH` to trigger TCP fallback |

## License

MIT
