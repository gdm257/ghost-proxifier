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

    // Load UDP stats for merging (non-blocking, uses last known data)
    json udpStats = GetUdpStats();
    std::map<DWORD, json> statMap;
    if (udpStats.is_array()) {
        for (auto& s : udpStats) {
            if (s.contains("pid")) statMap[static_cast<DWORD>(s["pid"])] = s;
        }
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

            // Merge UDP stats
            auto it = statMap.find(pe.th32ProcessID);
            if (it != statMap.end()) {
                const json& s = it->second;
                info.up = s.value("up", 0ULL);
                info.down = s.value("down", 0ULL);
                info.conns = s.value("conns", 0);
                info.latency = s.value("latency", -1);
                if (s.contains("node") && s["node"].is_string())
                    info.node = s["node"].get<std::string>();
                if (s.contains("dns") && s["dns"].is_string())
                    info.dns = s["dns"].get<std::string>();
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

void SetSystemProxy(bool enable, const std::string& proxyAddr) {
    HKEY hKey;
    LONG res = RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS) return;

    if (enable) {
        DWORD val = 1;
        RegSetValueExA(hKey, "ProxyEnable", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegSetValueExA(hKey, "ProxyServer", 0, REG_SZ,
                       (BYTE*)proxyAddr.c_str(), (DWORD)proxyAddr.size() + 1);
    } else {
        DWORD val = 0;
        RegSetValueExA(hKey, "ProxyEnable", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    }
    RegCloseKey(hKey);

    // Notify Windows of settings change
    InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionA(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
}

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

// ---- DNS Leak Check ----

bool CheckDnsLeak() {
    // Stub — extend with actual DNS leak detection logic.
    // A real implementation would:
    // 1. Resolve a test domain via standard system DNS (bypassing proxy).
    // 2. Resolve the same domain through the proxy (ghost_dns_dump.exe).
    // 3. Compare results — if they differ, DNS is leaking.
    return false;
}
