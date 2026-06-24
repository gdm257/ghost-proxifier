#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <cstdint>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Config path relative to exe
std::wstring GetConfigPath();

// Read/write config.json
json LoadConfig();
void SaveConfig(const json& cfg);

// Process info struct
struct ProcessInfo {
    DWORD pid = 0;
    std::wstring name;
    std::wstring path;
    DWORD parentPid = 0;
    bool injected = false;
    int latency = -1;
    uint64_t up = 0;
    uint64_t down = 0;
    int conns = 0;
    std::string node = "Direct";
    std::string dns = "System";
};

// Live stats received from injected DLLs via UDP
struct ProcessLiveStats {
    std::string guid;
    DWORD ppid = 0;
    uint64_t up = 0;
    uint64_t down = 0;
    int latency = -1;
    int conns = 0;
    std::string node = "Direct";
    std::string dns = "System";
    DWORD lastUpdate = 0; // GetTickCount() when received
};
extern std::map<DWORD, ProcessLiveStats> g_ProcessStats;
extern std::mutex g_ProcessStatsMutex;

// Parse a "[stats] ..." UDP message and update g_ProcessStats
void UpdateStatsFromMessage(const char* msg, int len);

// Enumerate running processes
std::vector<ProcessInfo> EnumerateProcesses();

// Get process tree (children of a PID, recursively)
std::vector<DWORD> GetProcessTree(DWORD parentPid);

// Check if a PID has ghost_core.dll loaded
bool IsProcessInjected(DWORD pid);

bool IsSystemProxyEnabled();

// DNS leak check
bool CheckDnsLeak();
