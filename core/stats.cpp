#include "globals.h"

// --- Global variables (stats module) ---
std::atomic<uint64_t> g_sentBytes{ 0 };
std::atomic<uint64_t> g_recvBytes{ 0 };
std::atomic<int> g_lastLatency{ 0 };

// --- StatsThread: periodic UDP stats reporting to CLI on port 45002 ---
DWORD WINAPI StatsThread(LPVOID) {
    while (true) {
        if (!g_Initialized) { Sleep(500); continue; }

        uint64_t up = g_sentBytes.load();
        uint64_t down = g_recvBytes.load();

        char stats[1024];
        std::string nodeName;
        std::string dnsMode;
        {
            std::lock_guard<std::mutex> lock(g_ConfigMutex);
            nodeName = g_Config.NodeName;
            dnsMode = g_Config.DnsMode;
        }

        int len = sprintf_s(stats, "[stats] guid:%s|pid:%d|ppid:%d|up:%llu|down:%llu|lat:%d|node:%s|dns:%s",
            g_CurrentGuid, GetCurrentProcessId(), GetParentProcessId(), up, down, g_lastLatency.load(), nodeName.c_str(), dnsMode.c_str());

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(45002);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        {
            std::lock_guard<std::mutex> lock(g_UdpMutex);
            if (g_CommonUdpSocket != INVALID_SOCKET) {
                sendto(g_CommonUdpSocket, stats, len, 0, (sockaddr*)&addr, sizeof(addr));
            }
        }

        Sleep(2000);
    }
    return 0;
}
