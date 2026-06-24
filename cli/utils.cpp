#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <fstream>
#include <map>
#include <tlhelp32.h>
#include <psapi.h>
#include <nlohmann/json.hpp>
#include "utils.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "psapi.lib")

using json = nlohmann::json;

// ---- Config ----

std::wstring GetConfigPath() {
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    std::wstring dir(buf);
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        dir = dir.substr(0, pos + 1);
    } else {
        dir = L".\\";
    }
    return dir + L"config.json";
}

json LoadConfig() {
    std::wstring path = GetConfigPath();
    char mbPath[MAX_PATH] = {};
    WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, mbPath, MAX_PATH, NULL, NULL);
    std::ifstream f(mbPath);
    if (!f.is_open()) return json::object();
    try {
        return json::parse(f);
    } catch (...) {
        return json::object();
    }
}

void SaveConfig(const json& cfg) {
    std::wstring path = GetConfigPath();
    char mbPath[MAX_PATH] = {};
    WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, mbPath, MAX_PATH, NULL, NULL);
    std::ofstream f(mbPath);
    if (f.is_open()) {
        f << cfg.dump(2);
    }
}

// ---- Process Enumeration ----

std::vector<ProcessInfo> EnumerateProcesses() {
    std::vector<ProcessInfo> result;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    // Snapshot live stats from injected DLLs
    std::map<DWORD, ProcessLiveStats> liveStats;
    {
        std::lock_guard<std::mutex> lock(g_ProcessStatsMutex);
        liveStats = g_ProcessStats;
    }

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo info = {};
            info.pid = pe.th32ProcessID;
            info.name = pe.szExeFile;
            info.parentPid = pe.th32ParentProcessID;

            // Get full path (skip idle/system processes PID 0/4)
            if (pe.th32ProcessID != 0 && pe.th32ProcessID != 4) {
                HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (h) {
                    wchar_t path[MAX_PATH] = {};
                    DWORD sz = MAX_PATH;
                    if (QueryFullProcessImageNameW(h, 0, path, &sz)) {
                        info.path = path;
                    }
                    info.injected = IsProcessInjected(pe.th32ProcessID);
                    CloseHandle(h);
                }
            }

            // Populate from live stats if available
            auto it = liveStats.find(info.pid);
            if (it != liveStats.end()) {
                info.up = it->second.up;
                info.down = it->second.down;
                info.latency = it->second.latency;
                info.conns = it->second.conns;
                info.node = it->second.node;
                info.dns = it->second.dns;
            }

            result.push_back(info);
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return result;
}

bool IsProcessInjected(DWORD pid) {
    if (pid == 0 || pid == 4) return false;

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return false;

    HMODULE mods[1024];
    DWORD needed = 0;
    bool found = false;
    if (EnumProcessModules(h, mods, sizeof(mods), &needed)) {
        DWORD count = (needed / sizeof(HMODULE));
        if (count > 1024) count = 1024;
        for (DWORD i = 0; i < count; i++) {
            wchar_t name[MAX_PATH] = {};
            if (GetModuleBaseNameW(h, mods[i], name, MAX_PATH)) {
                if (wcsstr(name, L"ghost_core")) {
                    found = true;
                    break;
                }
            }
        }
    }
    CloseHandle(h);
    return found;
}

// ---- System Proxy ----

bool IsSystemProxyEnabled() {
    HKEY hKey;
    LONG res = RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, KEY_READ, &hKey);
    if (res != ERROR_SUCCESS) return false;
    DWORD val = 0, sz = sizeof(val);
    RegQueryValueExA(hKey, "ProxyEnable", NULL, NULL, (BYTE*)&val, &sz);
    RegCloseKey(hKey);
    return val != 0;
}

// ---- Live Stats from injected DLLs (UDP) ----

std::map<DWORD, ProcessLiveStats> g_ProcessStats;
std::mutex g_ProcessStatsMutex;

void UpdateStatsFromMessage(const char* msg, int len) {
    if (!msg || len <= 0) return;
    std::string s(msg, len);
    if (s.find("[stats]") != 0) return;

    ProcessLiveStats st;
    // Parse key:value pairs separated by |
    // Format: [stats] guid:GUID|pid:PID|ppid:PPID|up:BYTES|down:BYTES|lat:MS|node:NAME|dns:MODE|blocked:0
    size_t pos = 7; // skip "[stats] "
    while (pos < s.length()) {
        size_t eq = s.find(':', pos);
        if (eq == std::string::npos) break;
        std::string key = s.substr(pos, eq - pos);
        size_t bar = s.find('|', eq + 1);
        if (bar == std::string::npos) bar = s.length();
        std::string val = s.substr(eq + 1, bar - eq - 1);

        if (key == "pid") {
            DWORD pid = (DWORD)strtoul(val.c_str(), NULL, 10);
            if (pid == 0) break; // invalid
            st.guid = ""; // will be set below
            st.lastUpdate = GetTickCount();
            // Continue parsing the rest into this stats struct
        } else if (key == "guid") {
            st.guid = val;
        } else if (key == "ppid") {
            st.ppid = (DWORD)strtoul(val.c_str(), NULL, 10);
        } else if (key == "up") {
            st.up = strtoull(val.c_str(), NULL, 10);
        } else if (key == "down") {
            st.down = strtoull(val.c_str(), NULL, 10);
        } else if (key == "lat") {
            st.latency = atoi(val.c_str());
        } else if (key == "conns") {
            st.conns = atoi(val.c_str());
        } else if (key == "node") {
            st.node = val;
        } else if (key == "dns") {
            st.dns = val;
        }

        pos = bar + 1;
        if (pos >= s.length()) break;
    }

    if (st.lastUpdate > 0) {
        // Find the PID key was parsed — re-parse to get it
        // We need to extract pid from the message
        size_t pidPos = s.find("|pid:");
        if (pidPos != std::string::npos) {
            size_t vStart = pidPos + 5;
            size_t vEnd = s.find('|', vStart);
            if (vEnd == std::string::npos) vEnd = s.length();
            DWORD pid = (DWORD)strtoul(s.substr(vStart, vEnd - vStart).c_str(), NULL, 10);
            if (pid > 0) {
                std::lock_guard<std::mutex> lock(g_ProcessStatsMutex);
                g_ProcessStats[pid] = st;
            }
        }
    }
}

// ---- DNS Leak Check ----

bool CheckDnsLeak() {
    // Stub — extend with actual DNS leak detection logic.
    // A real implementation would:
    // 1. Resolve a test domain via standard system DNS (bypassing proxy).
    // 2. Resolve the same domain through the proxy (ghost_dns_dump.exe).
    // 3. Compare results — if they differ, DNS is leaking.
    return false;
}
