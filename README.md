# Ghost Proxifier

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Process-level transparent proxy for Windows.** Inject a DLL into any process (and its children) to intercept all socket and DNS calls, routing traffic through an upstream proxy without application awareness.

## Quick Start

### Prerequisites

- **Visual Studio 2022** with "Desktop development with C++" workload
- **CMake** 3.15 or later
- **Git** (with submodule support)

### Build

```powershell
git clone --recursive https://github.com/liliBestCoder/ghost-proxifier.git
cd ghost-proxifier
.\compile.bat
```

`compile.bat` checks for submodules, then builds both 64-bit and 32-bit targets.

Output binaries:

| Binary | x64 Path | x86 Path |
|--------|----------|----------|
| CLI tool | `build_x64\cli\Release\ghost-proxifier.exe` | `build_x86\cli\Release\ghost-proxifier_x86.exe` |
| Core DLL | `build_x64\core\Release\ghost_core_x64.dll` | `build_x86\core\Release\ghost_core_x86.dll` |
| Launcher | `build_x64\core\Release\ghost_launcher_x64.exe` | `build_x86\core\Release\ghost_launcher_x86.exe` |
| DNS dump | `build_x64\core\Release\ghost_dns_dump.exe` | — |

For a manual build (x64 only):

```powershell
mkdir build_x64
cd build_x64
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

## Usage

All commands follow the pattern `ghost-proxifier <command> [options]`. Run without arguments to see the help.

### List & Status

```
ghost-proxifier list           # List all processes with proxy injection status
ghost-proxifier status         # Show global proxy state, upstream, and stats
```

### Inject & Eject

```
ghost-proxifier inject 1234             # Inject ghost_core.dll into process by PID
ghost-proxifier inject notepad.exe      # Inject by process name (first match)
ghost-proxifier inject --tree 1234      # Inject process + all child processes
ghost-proxifier eject 1234              # Unload DLL from process
```

### Proxy Control

```
ghost-proxifier proxy on               # Enable system-wide proxy
ghost-proxifier proxy off              # Disable system-wide proxy
```

### Upstream Configuration

```
ghost-proxifier config show            # Display current configuration
ghost-proxifier config upstream add myproxy 127.0.0.1:1080   # Add an upstream
ghost-proxifier config upstream rm myproxy                    # Remove an upstream
ghost-proxifier config upstream use myproxy                   # Switch active upstream
```

### DNS

```
ghost-proxifier config dns 1.1.1.1     # Set custom DNS server
ghost-proxifier dns check              # DNS leak detection test
```

### Monitor

```
ghost-proxifier monitor                # Real-time traffic monitor (Ctrl+C to quit)
```

## Configuration

On first run, Ghost Proxifier creates a `config.json` next to the executable if one does not exist. You can also place it in the working directory.

### `config.json` Format

```json
{
  "dns": {
    "enabled": true,
    "server": "8.8.8.8",
    "port": 53
  },
  "upstream": [
    {"id": "clash",     "name": "Clash Verge Rev",  "type": "Mixed", "addr": "127.0.0.1:7897",  "active": false, "builtin": true},
    {"id": "v2rayn",    "name": "v2rayN",           "type": "Mixed", "addr": "127.0.0.1:10807", "active": false, "builtin": true},
    {"id": "nekobox",   "name": "NekoBox",          "type": "Mixed", "addr": "127.0.0.1:2080",  "active": false, "builtin": true},
    {"id": "clashwin",  "name": "Clash for Windows","type": "Mixed", "addr": "127.0.0.1:7890",  "active": false, "builtin": true}
  ],
  "targets": []
}
```

| Field | Description |
|-------|-------------|
| `dns.enabled` | Whether to intercept and redirect DNS queries |
| `dns.server` | Upstream DNS server address |
| `dns.port` | Upstream DNS server port |
| `upstream[].id` | Unique identifier for the upstream |
| `upstream[].name` | Human-readable display name |
| `upstream[].type` | Protocol type (`Mixed` for SOCKS5+HTTP) |
| `upstream[].addr` | Address in `host:port` format |
| `upstream[].active` | Whether this upstream is currently selected |
| `upstream[].builtin` | Pre-shipped default (can be removed) |
| `targets` | List of target process names for automatic injection |

## How It Works

### Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  ghost-      │     │  ghost_core.dll  │     │  Upstream Proxy  │
│  proxifier   │────>│  (injected)      │────>│  (Clash/v2ray/  │
│  (CLI)       │     │                  │     │   SOCKS5)        │
└─────────────┘     └──────────────────┘     └──────────────────┘
       │                      │                        │
       │ UDP stats            │ Hook:                  │
       │ (port 18901)         │  - connect()           │
       │                      │  - WSAConnect()        │
       │                      │  - getaddrinfo()       │
       │                      │  - gethostbyname()     │
       │                      │  - CreateProcess()     │
       │                      │                        │
       ▼                      ▼                        ▼
  Real-time monitor    Intercepted socket     Proxied traffic
  (traffic stats)      calls redirected       exits to internet
```

1. **`ghost-proxifier` (CLI)** manages injection, configuration, and monitoring.
2. **`ghost_core.dll`** is injected into the target process via `SetThreadContext`-based shellcode injection. It hooks Windows socket APIs with MinHook.
3. **Hooked socket calls** (`connect`, `WSAConnect`, etc.) are redirected through the configured upstream proxy using HTTP CONNECT or SOCKS5.
4. **DNS queries** (`getaddrinfo`, `gethostbyname`) are intercepted and resolved through the upstream proxy to prevent leaks.
5. **Stats** are reported back to the CLI over UDP (port 18901) for the real-time monitor.

### Process Tree Injection

When you run `ghost-proxifier inject --tree <pid>`, Ghost Proxifier:

1. Injects `ghost_core.dll` into the target process.
2. Enumerates all child processes of the target using `CreateToolhelp32Snapshot`.
3. Recursively injects into each child, grandchild, and so on.
4. Hooks `CreateProcess` so any *new* child processes are automatically injected at birth.

This ensures complete coverage for applications that spawn worker processes (browsers, IDEs, build tools).

## Directory Structure

```
ghost-proxifier/
├── cli/                    # CLI tool source (commands, UDP client, process tree)
│   ├── main.cpp            # Entry point and command routing
│   ├── commands_*.cpp      # Individual command implementations
│   ├── process_tree.cpp    # Recursive child process enumeration
│   ├── udp_client.cpp      # Stats listener (UDP port 18901)
│   └── utils.cpp           # Shared helpers (NtQuerySystemInformation, etc.)
├── core/                   # Injection DLL source (ghost_core.dll)
│   ├── ghost_core.cpp      # DLL entry point, hook installation
│   ├── ghost_injector.cpp  # SetThreadContext shellcode injector
│   ├── injector.cpp        # Injector helper library
│   ├── hooks_socket.cpp    # Socket API hooks (connect, WSAConnect, ...)
│   ├── hooks_dns.cpp       # DNS API hooks (getaddrinfo, gethostbyname, ...)
│   ├── hooks_process.cpp   # CreateProcess hook for auto child injection
│   ├── proxy.cpp           # Upstream proxy connection (HTTP CONNECT / SOCKS5)
│   ├── dns.cpp             # DNS resolution via proxy
│   ├── dns_cache.cpp       # Shared-memory DNS cache
│   ├── dns_pool.cpp        # DNS connection pool
│   ├── config.cpp          # Runtime configuration loading
│   ├── stats.cpp           # UDP stats reporting
│   ├── shellcode.cpp       # x64/x86 shellcode for remote thread injection
│   ├── utils.cpp           # Logging, socket helpers, overlapped tracking
│   ├── globals.h           # Shared declarations and constants
│   ├── ghost_launcher.cpp  # Launcher helper
│   └── ghost_dns_dump.cpp  # DNS dump utility
├── third_party/            # Third-party dependencies
├── bin/                    # Pre-built binaries (optional)
├── config.json             # Default configuration
├── CMakeLists.txt          # Root CMake build
├── compile.bat             # One-click build script (x64 + x86)
└── LICENSE                 # MIT license
```

## License

MIT — see [LICENSE](LICENSE) for full text.
