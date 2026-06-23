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

// --- NetConfigHandshake: fetches proxy config from local CLI via UDP ---
void NetConfigHandshake() {
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(45002);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    char req[256];
    int reqLen = sprintf_s(req, "[req_cfg] guid:%s|pid:%d|ppid:%d", g_CurrentGuid, GetCurrentProcessId(), GetParentProcessId());

    std::lock_guard<std::mutex> lock(g_UdpMutex);
    if (g_CommonUdpSocket == INVALID_SOCKET) return;

    for (int retry = 0; retry < 20; retry++) {
        sendto(g_CommonUdpSocket, req, reqLen, 0, (sockaddr*)&addr, sizeof(addr));

        char buf[1024];
        int n = recv(g_CommonUdpSocket, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = 0;
            std::string resp = buf;
            if (resp.find("[resp_cfg]") == 0) {
                GlobalConfig new_cfg;
                size_t pP = resp.find("proxy:");
                size_t pE = resp.find("|", pP);
                if (pP != std::string::npos) new_cfg.ProxyIP = resp.substr(pP + 6, pE - (pP + 6));

                size_t portP = resp.find("port:");
                size_t portE = resp.find("|", portP);
                if (portP != std::string::npos) new_cfg.ProxyPort = std::stoi(resp.substr(portP + 5, portE - (portP + 5)));

                size_t nodeP = resp.find("node:");
                size_t nodeE = resp.find("|", nodeP);
                if (nodeP != std::string::npos) new_cfg.NodeName = resp.substr(nodeP + 5, nodeE - (nodeP + 5));

                size_t dnsMP = resp.find("dns_mode:");
                size_t dnsME = resp.find("|", dnsMP);
                if (dnsMP != std::string::npos) new_cfg.DnsMode = resp.substr(dnsMP + 9, dnsME - (dnsMP + 9));

                size_t dnsIP = resp.find("dns_ip:");
                size_t dnsIE = resp.find("|", dnsIP);
                if (dnsIP != std::string::npos) new_cfg.DnsIP = resp.substr(dnsIP + 7, dnsIE - (dnsIP + 7));

                size_t dnsPP = resp.find("dns_port:");
                size_t dnsPE = resp.find("|", dnsPP);
                if (dnsPP != std::string::npos) new_cfg.DnsProxyPort = std::stoi(resp.substr(dnsPP + 9, dnsPE - (dnsPP + 9)));

                size_t syncP = resp.find("sync:");
                if (syncP != std::string::npos) new_cfg.SyncHandshake = (resp.substr(syncP + 5, 1) == "1");

                wchar_t syncEnv[16] = { 0 };
                DWORD syncEnvLen = GetEnvironmentVariableW(L"GHOST_SYNC_HANDSHAKE", syncEnv, 16);
                if (syncEnvLen > 0 && wcscmp(syncEnv, L"1") == 0) {
                    new_cfg.SyncHandshake = true;
                }

                std::lock_guard<std::mutex> lock(g_ConfigMutex);
                g_Config = new_cfg;
                return; // Success
            }
        }
        Sleep(50); // Short delay between retries
    }
}

// --- PerformLazyInitializationInternal: background engine setup ---
void PerformLazyInitializationInternal() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitUdpSocket();
    NetConfigHandshake();

    extern DWORD WINAPI DnsProxyThread(LPVOID);
    extern DWORD WINAPI StatsThread(LPVOID);
    CreateThread(NULL, 0, DnsProxyThread, NULL, 0, NULL);
    CreateThread(NULL, 0, StatsThread, NULL, 0, NULL);

    NetLog("[Proxy] Lazy initialization complete.");
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

// --- StartStats: kick off background initialization + stats ---
void StartStats(){
    InitUdpSocket(); // Ensure socket is ready for NetLog
    CreateThread(NULL, 0, DelayedInitThread, NULL, 0, NULL);
}

// --- LoadConfigFromEnv: reads GHOST_* environment variables ---
void LoadConfigFromEnv() {
    char buf[256];
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        // GHOST_PROXY + GHOST_PROXY_PORT (set by UI AppendGhostEnvVars)
        if (GetEnvironmentVariableA("GHOST_PROXY", buf, sizeof(buf))) {
            g_Config.ProxyIP = buf;
        }
        if (GetEnvironmentVariableA("GHOST_PROXY_PORT", buf, sizeof(buf))) {
            g_Config.ProxyPort = atoi(buf);
        }
        // GHOST_DNS + GHOST_DNS_PORT + GHOST_DNS_MODE
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
    }
    NetLog("[Cfg] Loaded from env: proxy=%s:%d node=%s dns=%s:%d mode=%s sync=%d",
        g_Config.ProxyIP.c_str(), g_Config.ProxyPort,
        g_Config.NodeName.c_str(),
        g_Config.DnsIP.c_str(), g_Config.DnsProxyPort, g_Config.DnsMode.c_str(),
        g_Config.SyncHandshake ? 1 : 0);
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
    NetLog("[Cfg] Env injected for child processes.");
}
