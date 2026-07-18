#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <tlhelp32.h>
#include <psapi.h>
#include <shellapi.h>
#include "utils.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")

// Get the directory where this exe lives
static std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    std::wstring dir(buf);
    size_t pos = dir.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? dir.substr(0, pos + 1) : L".\\";
}

// Determine if target process is 64-bit
// On 64-bit Windows: check if process is NOT running under WOW64
static bool IsProcess64Bit(DWORD pid) {
#ifdef _WIN64
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        // Can't query — try native API as fallback using the PID itself.
        // On x64 Windows, if IsWow64Process fails, we can infer from the OS:
        // the system can create both x64 and x86 processes. Default to x64
        // for system/high-integrity processes, but x86 is also possible.
        return true; // best guess for system processes
    }
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(h, &isWow64)) {
        CloseHandle(h);
        return true; // Can't determine — assume native (x64)
    }
    CloseHandle(h);
    return !isWow64; // TRUE if native x64, FALSE if running under WOW64 (x86)
#else
    (void)pid;
    return false;
#endif
}

// Find PID by process name (exe name without path)
static std::vector<DWORD> FindPidsByName(const std::wstring& name) {
    std::vector<DWORD> result;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {
                result.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return result;
}

// Resolve PIDs from argument (numeric PID or process name, may return multiple)
static bool ResolvePids(const wchar_t* arg, std::vector<DWORD>& outPids) {
    // Try numeric PID first
    wchar_t* end = nullptr;
    DWORD pid = wcstoul(arg, &end, 10);
    if (end && *end == 0 && pid > 0) {
        outPids.push_back(pid);
        return true;
    }

    // Process name lookup
    outPids = FindPidsByName(arg);
    if (!outPids.empty()) return true;

    fprintf(stderr, "Error: No process found matching '%ls'\n", arg);
    return false;
}

// Enable SeDebugPrivilege to bypass DACL deny entries on protected processes.
// No-op if not running as admin.
static void EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);
}

// Write ghost_config.ini next to the DLL so the injected DLL can read its
// config without relying on environment variables (which belong to the host
// process, not the target).  Matches the original ghost.conf approach.
static void WriteConfigForDll(const std::wstring& dllPath) {
    // Build config file path: <dllDir>\ghost_config.ini
    std::wstring cfgPath = dllPath;
    size_t slash = cfgPath.find_last_of(L"\\/");
    if (slash != std::wstring::npos) cfgPath = cfgPath.substr(0, slash + 1);
    else cfgPath = L"";
    cfgPath += L"ghost_config.ini";

    std::ofstream f(cfgPath);
    if (!f.is_open()) return;

    char buf[256];
    if (GetEnvironmentVariableA("GHOST_PROXY", buf, sizeof(buf)))
        f << "proxy=" << buf << "\n";
    if (GetEnvironmentVariableA("GHOST_PROXY_PORT", buf, sizeof(buf)))
        f << "port=" << buf << "\n";
    if (GetEnvironmentVariableA("GHOST_DNS", buf, sizeof(buf)))
        f << "dns=" << buf << "\n";
    if (GetEnvironmentVariableA("GHOST_DNS_PORT", buf, sizeof(buf)))
        f << "dns_port=" << buf << "\n";
    if (GetEnvironmentVariableA("GHOST_DNS_MODE", buf, sizeof(buf)))
        f << "dns_mode=" << buf << "\n";
    if (GetEnvironmentVariableA("GHOST_NODE", buf, sizeof(buf)))
        f << "node=" << buf << "\n";
    if (GetEnvironmentVariableA("GHOST_SYNC", buf, sizeof(buf)))
        f << "sync=" << buf << "\n";
    if (GetEnvironmentVariableA("GHOST_LOG_PORT", buf, sizeof(buf)))
        f << "log_port=" << buf << "\n";
    if (GetEnvironmentVariableA("GHOST_STATS_PORT", buf, sizeof(buf)))
        f << "stats_port=" << buf << "\n";
}

// Direct injection — matches the original ghost_injector.cpp approach.
// Opens the target with PROCESS_ALL_ACCESS, writes DLL path, creates remote thread.
// Returns 0 on success, or error code (same codes as ghost_launcher.exe).
static DWORD DirectInject(DWORD pid, const std::wstring& dllPath) {
    EnableDebugPrivilege();

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) return 2;

    void* loadLibraryAddr = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        CloseHandle(h);
        return 3;
    }

    // Convert wide path to ANSI for LoadLibraryA
    int pathLenA = WideCharToMultiByte(CP_ACP, 0, dllPath.c_str(), -1, NULL, 0, NULL, NULL);
    if (pathLenA <= 0) {
        CloseHandle(h);
        return 3;
    }
    std::string pathA(pathLenA, '\0');
    WideCharToMultiByte(CP_ACP, 0, dllPath.c_str(), -1, &pathA[0], pathLenA, NULL, NULL);

    void* m = VirtualAllocEx(h, NULL, pathLenA, MEM_COMMIT, PAGE_READWRITE);
    if (!m) {
        CloseHandle(h);
        return 4;
    }

    if (!WriteProcessMemory(h, m, pathA.c_str(), pathLenA, NULL)) {
        VirtualFreeEx(h, m, 0, MEM_RELEASE);
        CloseHandle(h);
        return 5;
    }

    HANDLE t = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, m, 0, NULL);
    if (t) {
        DWORD waitResult = WaitForSingleObject(t, 10000);
        DWORD loadResult = 0;
        bool ok = waitResult == WAIT_OBJECT_0 &&
                  GetExitCodeThread(t, &loadResult) &&
                  loadResult != 0;
        CloseHandle(t);
        VirtualFreeEx(h, m, 0, MEM_RELEASE);
        CloseHandle(h);
        return ok ? 0 : 8;
    }

    VirtualFreeEx(h, m, 0, MEM_RELEASE);
    CloseHandle(h);
    return 6;
}

// Fallback: try injecting via ghost_launcher.exe (for cross-arch scenarios
// like x64 CLI injecting into x86 process, or when direct injection fails).
static bool TryLauncherInject(DWORD pid, const std::wstring& launcherPath,
                               const std::wstring& dllPath, bool elevated) {
    std::wstring params = std::to_wstring(pid) + L" \"" + dllPath + L"\"";

    if (elevated) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        sei.lpVerb = L"runas";
        sei.lpFile = launcherPath.c_str();
        sei.lpParameters = params.c_str();
        sei.nShow = SW_HIDE;

        if (!ShellExecuteExW(&sei)) return false;
        if (!sei.hProcess) return false;

        WaitForSingleObject(sei.hProcess, 15000);
        DWORD exitCode = 1;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);
        return exitCode == 0;
    }

    std::wstring cmd = L"\"" + launcherPath + L"\" " + params;
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return false;

    WaitForSingleObject(pi.hProcess, 15000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode == 0;
}

// Inject DLL into a single process.
// Tries direct injection first (matching the original ghost_injector approach),
// then falls back to launcher for cross-arch or protected processes.
static bool InjectOne(DWORD pid) {
    std::wstring exeDir = GetExeDir();
    bool target64 = IsProcess64Bit(pid);

    std::wstring launcherPath;
    std::wstring dllPath;

    if (target64) {
        launcherPath = exeDir + L"ghost_launcher_x64.exe";
        dllPath = exeDir + L"ghost_core_x64.dll";
    } else {
        launcherPath = exeDir + L"ghost_launcher_x86.exe";
        dllPath = exeDir + L"ghost_core_x86.dll";
    }

    // Check DLL exists
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Error: DLL not found: %ls\n", dllPath.c_str());
        return false;
    }

#ifdef _WIN64
    bool crossArch = !target64; // x64 CLI injecting into x86 target
#else
    bool crossArch = target64;  // x86 CLI injecting into x64 target
#endif

    // 0. Write config file next to DLL so the target process can read it
    WriteConfigForDll(dllPath);

    // 1. Direct injection (matches original ghost_injector approach)
    if (!crossArch) {
        DWORD result = DirectInject(pid, dllPath);
        if (result == 0) {
            printf("  Injected PID %lu (%s)\n", pid, target64 ? "x64" : "x86");
            return true;
        }

        // On access denied, try elevated launcher before giving up
        if (result == 2) {
            fprintf(stderr, "  PID %lu: access denied — retrying elevated...\n", pid);
            if (TryLauncherInject(pid, launcherPath, dllPath, true)) {
                printf("  Injected PID %lu (%s) [elevated]\n", pid, target64 ? "x64" : "x86");
                return true;
            }
        }

        const char* errMsg = "Unknown error";
        switch (result) {
            case 2: errMsg = "Cannot open process (access denied)"; break;
            case 3: errMsg = "Cannot find LoadLibraryW address"; break;
            case 4: errMsg = "Cannot allocate memory in target process"; break;
            case 5: errMsg = "Cannot write DLL path to target process"; break;
            case 6: errMsg = "Cannot create remote thread"; break;
            case 8: errMsg = "DLL load failed (LoadLibraryW returned NULL)"; break;
        }
        fprintf(stderr, "Error: Injection failed for PID %lu: %s (code %lu)\n",
                pid, errMsg, result);
        return false;
    }

    // 2. Cross-arch: must use launcher
    if (GetFileAttributesW(launcherPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Error: Launcher not found: %ls\n", launcherPath.c_str());
        return false;
    }

    if (TryLauncherInject(pid, launcherPath, dllPath, false) ||
        TryLauncherInject(pid, launcherPath, dllPath, true)) {
        printf("  Injected PID %lu (%s)\n", pid, target64 ? "x64" : "x86");
        return true;
    }

    fprintf(stderr, "Error: Injection failed for PID %lu (cross-arch launcher)\n", pid);
    return false;
}

// ---- Live Log Listener ----
static volatile bool g_logRunning = true;

static BOOL WINAPI LogCtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_BREAK_EVENT) {
        g_logRunning = false;
        return TRUE;
    }
    return FALSE;
}

static const char* TagColor(const char* tag) {
    if (!tag || !*tag) return "\x1b[0m";
    if (strstr(tag, "FAILED") || strstr(tag, "fail") || strstr(tag, "Error") || strstr(tag, "error"))
        return "\x1b[31m";
    if (strstr(tag, "DNS"))
        return "\x1b[36m";
    if (strstr(tag, "Proxy") || strstr(tag, "Handshake"))
        return "\x1b[33m";
    if (strstr(tag, "hook"))
        return "\x1b[35m";
    if (strstr(tag, "Init"))
        return "\x1b[1;37m";
    if (strstr(tag, "Cache"))
        return "\x1b[32m";
    return "\x1b[0m";
}

// Print a single colorized log line. Stats messages are parsed into the
// global stats map instead of being printed.
static void PrintLogLine(char* buf, int len) {
    if (len <= 0) return;
    buf[len] = '\0';

    // Stats messages go to the process stats table, not the log output
    if (strncmp(buf, "[stats]", 7) == 0) {
        UpdateStatsFromMessage(buf, len);
        return;
    }

    const char* color = "\x1b[0m";
    const char* p = buf;
    if (*p == '[') { while (*p && *p != ']') p++; if (*p) p++; if (*p == ' ') p++; }
    if (*p == '[') { while (*p && *p != ']') p++; if (*p) p++; if (*p == ' ') p++; }
    color = TagColor(p);
    printf("%s%s\x1b[0m\n", color, buf);
    fflush(stdout);
}

// Log listener for --now mode (inject existing processes, then show logs)
static void RunLogListener(SOCKET logSock, size_t injectedCount) {
    SetConsoleCtrlHandler(LogCtrlHandler, TRUE);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode))
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    printf("\n--- Live Log (%zu process(es) injected) ---\n", injectedCount);
    printf("Press Ctrl+C to stop.\n\n");

    char buf[2048];
    while (g_logRunning) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(logSock, &rfds);
        timeval tv = { 1, 0 };
        int sel = select(0, &rfds, NULL, NULL, &tv);
        if (sel < 0) break;
        if (sel == 0) continue;

        int n = recv(logSock, buf, sizeof(buf) - 1, 0);
        PrintLogLine(buf, n);
    }

    SetConsoleCtrlHandler(LogCtrlHandler, FALSE);
    printf("\nLog listener stopped.\n");
}

// Watch + Log listener for default inject mode.
// Polls for new instances of targetName and injects immediately on discovery,
// while simultaneously showing live UDP logs from injected processes.
static void RunWatchLogListener(SOCKET logSock, const std::wstring& targetName, bool treeMode, int alreadyInjected) {
    SetConsoleCtrlHandler(LogCtrlHandler, TRUE);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode))
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    // Snapshot already-known PIDs so we don't double-inject
    std::set<DWORD> knownPids;
    {
        auto initial = FindPidsByName(targetName);
        knownPids.insert(initial.begin(), initial.end());
    }

    if (alreadyInjected > 0) {
        printf("\n--- Live Log (%d process(es) injected) + Watching for new %ls ---\n",
               alreadyInjected, targetName.c_str());
    } else {
        printf("\nWatching for %ls... (new instances will be injected immediately)\n", targetName.c_str());
        if (!knownPids.empty()) {
            printf("Note: %zu existing %ls process(es) detected — use --now to inject them instead.\n",
                   knownPids.size(), targetName.c_str());
        }
    }
    printf("Press Ctrl+C to stop.\n\n");

    int watchInjected = 0;
    DWORD lastPoll = 0; // poll immediately on first iteration
    char buf[2048];

    while (g_logRunning) {
        // Poll for new processes every 200 ms
        DWORD tick = GetTickCount();
        if (tick - lastPoll >= 200) {
            lastPoll = tick;
            auto current = FindPidsByName(targetName);
            for (auto pid : current) {
                if (knownPids.find(pid) == knownPids.end()) {
                    knownPids.insert(pid);

                    std::vector<DWORD> injectPids;
                    injectPids.push_back(pid);
                    if (treeMode) {
                        auto children = GetProcessTree(pid);
                        injectPids.insert(injectPids.end(), children.begin(), children.end());
                    }

                    for (auto injPid : injectPids) {
                        if (InjectOne(injPid)) {
                            watchInjected++;
                        }
                    }
                }
            }
        }

        // Check UDP log socket (200 ms timeout so poll stays responsive)
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(logSock, &rfds);
        timeval tv = { 0, 200000 };
        int sel = select(0, &rfds, NULL, NULL, &tv);
        if (sel < 0) break;
        if (sel > 0) {
            int n = recv(logSock, buf, sizeof(buf) - 1, 0);
            PrintLogLine(buf, n);
        }
    }

    SetConsoleCtrlHandler(LogCtrlHandler, FALSE);
    printf("\nWatch stopped. %d new process(es) injected.\n", watchInjected);
}

// ---- cmd_inject ----
// Usage: inject <pid>               — inject existing process immediately
//        inject <name>              — watch for process to start, inject instantly
//        inject --tree <pid|name>   — also inject child processes

int cmd_inject(int argc, wchar_t* argv[]) {
    bool treeMode = false;
    int argIdx = 2;

    while (argIdx < argc && wcscmp(argv[argIdx], L"--tree") == 0) {
        treeMode = true;
        argIdx++;
    }

    if (argc <= argIdx) {
        fprintf(stderr, "Usage: ghost-proxifier inject [--tree] <pid|name>\n");
        return 1;
    }

    // Check if argument is a numeric PID (inject existing, no watch)
    wchar_t* end = nullptr;
    DWORD numericPid = wcstoul(argv[argIdx], &end, 10);
    bool isNumericPid = (end && *end == 0 && numericPid > 0);

    std::wstring targetName = argv[argIdx];

    // Allocate UDP log listener port (OS picks a free port)
    SOCKET logSock = INVALID_SOCKET;
    int logPort = 0;
    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        logSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (logSock != INVALID_SOCKET) {
            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            addr.sin_port = 0;
            if (bind(logSock, (sockaddr*)&addr, sizeof(addr)) == 0) {
                int addrLen = sizeof(addr);
                getsockname(logSock, (sockaddr*)&addr, &addrLen);
                logPort = ntohs(addr.sin_port);
                char portStr[16];
                snprintf(portStr, sizeof(portStr), "%d", logPort);
                SetEnvironmentVariableA("GHOST_LOG_PORT", portStr);
                SetEnvironmentVariableA("GHOST_STATS_PORT", "45002");
            } else {
                closesocket(logSock);
                logSock = INVALID_SOCKET;
            }
        }
    }

    // Export config.json to environment variables so WriteConfigForDll
    // can write ghost_config.ini for the injected DLL.
    {
        json cfg = LoadConfig();

        if (cfg.contains("upstream") && cfg["upstream"].is_array()) {
            for (auto& u : cfg["upstream"]) {
                if (u.value("active", false)) {
                    std::string addr = u.value("addr", "");
                    size_t colon = addr.find(':');
                    if (colon != std::string::npos) {
                        SetEnvironmentVariableA("GHOST_PROXY", addr.substr(0, colon).c_str());
                        SetEnvironmentVariableA("GHOST_PROXY_PORT", addr.substr(colon + 1).c_str());
                    }
                    std::string name = u.value("name", "");
                    SetEnvironmentVariableA("GHOST_NODE", name.empty() ? "Auto" : name.c_str());
                    break;
                }
            }
        }

        if (cfg.contains("dns") && cfg["dns"].is_object()) {
            std::string server = cfg["dns"].value("server", "8.8.8.8");
            SetEnvironmentVariableA("GHOST_DNS", server.c_str());
            int dnsPort = cfg["dns"].value("port", 53);
            char dnsPortBuf[16];
            snprintf(dnsPortBuf, sizeof(dnsPortBuf), "%d", dnsPort);
            SetEnvironmentVariableA("GHOST_DNS_PORT", dnsPortBuf);
            bool dnsEnabled = cfg["dns"].value("enabled", true);
            SetEnvironmentVariableA("GHOST_DNS_MODE", dnsEnabled ? "dot" : "system");
        }
    }

    if (isNumericPid) {
        // Numeric PID: inject existing process immediately
        std::vector<DWORD> pids;
        pids.push_back(numericPid);
        if (treeMode) {
            auto children = GetProcessTree(numericPid);
            pids.insert(pids.end(), children.begin(), children.end());
        }

        printf("Injecting %zu process(es)...\n", pids.size());

        int successCount = 0;
        for (auto pid : pids) {
            if (InjectOne(pid)) successCount++;
        }
        printf("Done: %d succeeded, %zu failed\n", successCount, pids.size() - successCount);

        if (logSock != INVALID_SOCKET) {
            RunLogListener(logSock, successCount);
            closesocket(logSock);
        }
        return (successCount == pids.size()) ? 0 : 1;
    }

    // Process name: watch mode — wait for process to start, inject instantly
    // before it creates any connections
    if (logSock != INVALID_SOCKET) {
        RunWatchLogListener(logSock, targetName, treeMode, 0);
        closesocket(logSock);
    }
    return 0;
}

// ---- cmd_eject ----
// Usage: eject <pid>
// Unload ghost_core.dll from the target process via CreateRemoteThread(FreeLibrary)

int cmd_eject(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: ghost-proxifier eject <pid>\n");
        return 1;
    }

    DWORD pid = 0;
    std::vector<DWORD> ejectPids;
    if (!ResolvePids(argv[2], ejectPids)) {
        return 1;
    }

    // Eject from all matching processes
    int okCount = 0, failCount = 0;
    for (auto pid : ejectPids) {
        printf("Ejecting ghost_core from PID %lu...\n", pid);
        bool ok = false;

        HANDLE h = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ | PROCESS_VM_OPERATION,
            FALSE, pid);
        if (!h) {
            fprintf(stderr, "  Error: Cannot open process %lu (error %lu)\n", pid, GetLastError());
            failCount++;
            continue;
        }

        HMODULE mods[1024];
        DWORD needed = 0;
        bool found = false;

        if (EnumProcessModules(h, mods, sizeof(mods), &needed)) {
            DWORD count = needed / sizeof(HMODULE);
            if (count > 1024) count = 1024;

            for (DWORD i = 0; i < count; i++) {
                wchar_t name[MAX_PATH] = {};
                if (GetModuleBaseNameW(h, mods[i], name, MAX_PATH)) {
                    if (wcsstr(name, L"ghost_core")) {
                        printf("  Found: %ls at 0x%p\n", name, mods[i]);

                        LPTHREAD_START_ROUTINE freeLib =
                            (LPTHREAD_START_ROUTINE)GetProcAddress(
                                GetModuleHandleA("kernel32.dll"), "FreeLibrary");

                        if (!freeLib) {
                            fprintf(stderr, "  Error: Cannot find FreeLibrary address\n");
                            break;
                        }

                        HANDLE t = CreateRemoteThread(h, NULL, 0, freeLib,
                                                      mods[i], 0, NULL);
                        if (!t) {
                            fprintf(stderr, "  Error: Cannot create remote thread (error %lu)\n",
                                    GetLastError());
                            break;
                        }

                        WaitForSingleObject(t, 5000);
                        DWORD exitCode = 0;
                        GetExitCodeThread(t, &exitCode);
                        CloseHandle(t);

                        if (exitCode) {
                            printf("  Unloaded successfully\n");
                            found = true;
                            ok = true;
                        } else {
                            fprintf(stderr, "  Error: FreeLibrary returned NULL\n");
                        }
                        break;
                    }
                }
            }
        }

        CloseHandle(h);

        if (!found) {
            fprintf(stderr, "  Error: ghost_core not found in process %lu\n", pid);
            failCount++;
        } else if (ok) {
            okCount++;
        } else {
            failCount++;
        }
    }

    printf("Eject done: %d succeeded, %d failed\n", okCount, failCount);
    return failCount > 0 ? 1 : 0;
}
