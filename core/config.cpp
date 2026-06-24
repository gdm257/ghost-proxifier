#include "globals.h"

// --- Global variable definitions (config module) ---
GlobalConfig g_Config;
std::mutex g_ConfigMutex;
char g_CurrentGuid[64] = "";
time_t g_InjectTime = 0;
std::atomic<bool> g_Initialized{ false };
std::atomic<bool> g_ProxyEngineInitialized{ false };
std::mutex g_EngineInitMutex;
std::atomic<int> g_DnsProxyPort{ 0 };

// --- PerformLazyInitializationInternal: background engine setup ---
void PerformLazyInitializationInternal() {
    // DNS proxy thread is already started in SetupThreadInternal.
    // This function exists as a gate target — no additional init needed.
}

// --- PerformLazyInitialization: thread-safe lazy init gate ---
void PerformLazyInitialization() {
    if (g_ProxyEngineInitialized) return;

    // Separate scope for lock_guard to avoid C2712
    {
        std::lock_guard<std::mutex> lock(g_EngineInitMutex);
        if (g_ProxyEngineInitialized) return;
        g_ProxyEngineInitialized = true;
    }

    PerformLazyInitializationInternal();
}

// --- DelayedInitThread: 2-second delayed background init ---
DWORD WINAPI DelayedInitThread(LPVOID) {
    Sleep(2000);
    PerformLazyInitialization();
    return 0;
}

// --- LoadConfigFromEnv: reads GHOST_* environment variables ---
// Falls back to ghost_config.ini in DLL directory if env vars not set.
void LoadConfigFromEnv() {
    char buf[256];
    bool gotEnv = false;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        if (GetEnvironmentVariableA("GHOST_PROXY", buf, sizeof(buf))) {
            g_Config.ProxyIP = buf; gotEnv = true;
        }
        if (GetEnvironmentVariableA("GHOST_PROXY_PORT", buf, sizeof(buf))) {
            g_Config.ProxyPort = atoi(buf);
        }
        if (GetEnvironmentVariableA("GHOST_DNS", buf, sizeof(buf))) {
            g_Config.DnsIP = buf;
        }
        if (GetEnvironmentVariableA("GHOST_DNS_PORT", buf, sizeof(buf))) {
            g_Config.DnsProxyPort = atoi(buf);
        }
        if (GetEnvironmentVariableA("GHOST_DNS_MODE", buf, sizeof(buf))) {
            g_Config.DnsMode = buf;
        }
        if (GetEnvironmentVariableA("GHOST_NODE", buf, sizeof(buf))) {
            g_Config.NodeName = buf;
        }
        if (GetEnvironmentVariableA("GHOST_SYNC", buf, sizeof(buf))) {
            g_Config.SyncHandshake = (atoi(buf) != 0);
        }
        if (GetEnvironmentVariableA("GHOST_LOG_PORT", buf, sizeof(buf))) {
            g_LogPort = atoi(buf);
        }
    }

    // Fallback: read ghost_config.ini from DLL directory (matches original ghost.conf)
    if (!gotEnv) {
        char dllPath[MAX_PATH] = "";
        if (g_hDllModule) GetModuleFileNameA(g_hDllModule, dllPath, MAX_PATH);
        char* lastSlash = strrchr(dllPath, '\\');
        if (lastSlash) {
            strcpy_s(lastSlash + 1, MAX_PATH - (lastSlash + 1 - dllPath), "ghost_config.ini");
        }
        std::ifstream file(dllPath);
        if (file.is_open()) {
            std::lock_guard<std::mutex> lock(g_ConfigMutex);
            std::string line;
            while (std::getline(file, line)) {
                if (line.empty() || line[0] == '#') continue;
                size_t eq = line.find('=');
                if (eq == std::string::npos) continue;
                std::string key = line.substr(0, eq);
                std::string val = line.substr(eq + 1);
                if (key == "proxy")      g_Config.ProxyIP = val;
                else if (key == "port")  g_Config.ProxyPort = atoi(val.c_str());
                else if (key == "dns")   g_Config.DnsIP = val;
                else if (key == "dns_port") g_Config.DnsProxyPort = atoi(val.c_str());
                else if (key == "dns_mode") g_Config.DnsMode = val;
                else if (key == "node")  g_Config.NodeName = val;
                else if (key == "sync")  g_Config.SyncHandshake = (val == "1");
                else if (key == "log_port") g_LogPort = atoi(val.c_str());
            }
        }
    }
}

// --- EnvInjectFromConfig: writes current config to GHOST_* env vars ---
void EnvInjectFromConfig() {
    std::lock_guard<std::mutex> lock(g_ConfigMutex);
    char buf[64];
    SetEnvironmentVariableA("GHOST_PROXY", g_Config.ProxyIP.c_str());
    snprintf(buf, sizeof(buf), "%d", g_Config.ProxyPort);
    SetEnvironmentVariableA("GHOST_PROXY_PORT", buf);
    SetEnvironmentVariableA("GHOST_DNS", g_Config.DnsIP.c_str());
    snprintf(buf, sizeof(buf), "%d", g_Config.DnsProxyPort);
    SetEnvironmentVariableA("GHOST_DNS_PORT", buf);
    SetEnvironmentVariableA("GHOST_DNS_MODE", g_Config.DnsMode.c_str());
    SetEnvironmentVariableA("GHOST_NODE", g_Config.NodeName.c_str());
    SetEnvironmentVariableA("GHOST_SYNC", g_Config.SyncHandshake ? "1" : "0");
    snprintf(buf, sizeof(buf), "%d", g_LogPort);
    SetEnvironmentVariableA("GHOST_LOG_PORT", buf);
    SetEnvironmentVariableA("GHOST_STATS_PORT", "45002");
}
