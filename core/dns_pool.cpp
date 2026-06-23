#include "globals.h"

// --- DNS Connection Pool globals ---
std::vector<DnsPoolConn> g_DnsPool;
std::mutex g_DnsPoolMutex;

SOCKET CreateDnsConn() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    std::string proxyIP, dnsIP;
    int proxyPort, dnsPort;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        proxyIP = g_Config.ProxyIP;
        proxyPort = g_Config.ProxyPort;
        dnsIP = g_Config.DnsIP;
        dnsPort = g_Config.DnsPort;
    }
    sockaddr_in p_addr;
    p_addr.sin_family = AF_INET;
    p_addr.sin_addr.s_addr = inet_addr(proxyIP.c_str());
    p_addr.sin_port = htons(proxyPort);
    if (!real_connect || real_connect(s, (sockaddr*)&p_addr, sizeof(p_addr)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt));
    std::string empty;
    if (!PerformHttpConnect(s, dnsIP.c_str(), dnsPort, AF_INET, empty)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

SOCKET AcquireDnsConn() {
    std::lock_guard<std::mutex> lock(g_DnsPoolMutex);
    DWORD now = GetTickCount();
    while (!g_DnsPool.empty()) {
        DnsPoolConn conn = g_DnsPool.back();
        g_DnsPool.pop_back();
        if (now - conn.last_used < DNS_POOL_IDLE_MS) {
            // Quick liveness check: if select says readable, connection is dead (FIN/RST)
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(conn.sock, &rfds);
            timeval tv = { 0, 0 };
            if (select(0, &rfds, NULL, NULL, &tv) == 0) {
                return conn.sock; // alive
            }
        }
        closesocket(conn.sock);
    }
    return INVALID_SOCKET;
}

void ReleaseDnsConn(SOCKET s) {
    std::lock_guard<std::mutex> lock(g_DnsPoolMutex);
    if ((int)g_DnsPool.size() >= DNS_POOL_MAX) {
        closesocket(s);
        return;
    }
    g_DnsPool.push_back({ s, GetTickCount() });
}
