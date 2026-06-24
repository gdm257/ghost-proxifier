#include "globals.h"

// --- Pending Proxy globals ---
std::unordered_map<SOCKET, PendingProxy> g_PendingProxySockets;
std::mutex g_PendingMutex;

// --- Proxy-Completed Sockets ---
std::unordered_set<SOCKET> g_ProxyCompletedSockets;
std::mutex g_ProxyCompletedMutex;

// --- PerformHttpConnect: HTTP CONNECT tunnel through proxy ---
bool PerformHttpConnect(SOCKET s, const char* ip_str, int port, int family, const std::string& domain) {
    char request[512];
    int req_len = 0;

    std::string proxyIP;
    int proxyPort;
    std::string dnsIP;
    int dnsPort;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        proxyIP = g_Config.ProxyIP;
        proxyPort = g_Config.ProxyPort;
        dnsIP = g_Config.DnsIP;
        dnsPort = g_Config.DnsPort;
    }

    const char* final_host = (!domain.empty()) ? domain.c_str() : ((port == 53 || port == dnsPort) ? dnsIP.c_str() : ip_str);

    // Auto-detect if brackets are needed (IPv6 literals only)
    bool use_brackets = (strchr(final_host, ':') != NULL);

    if (use_brackets) {
        req_len = sprintf_s(
            request,
            "CONNECT [%s]:%d HTTP/1.1\x0d\x0aHost: [%s]:%d\x0d\x0aProxy-Connection: Keep-Alive\x0d\x0aUser-Agent: GhostProxifier/1.0\x0d\x0a\x0d\x0a",
            final_host, port, final_host, port);
    }
    else {
        req_len = sprintf_s(
            request,
            "CONNECT %s:%d HTTP/1.1\x0d\x0aHost: %s:%d\x0d\x0aProxy-Connection: Keep-Alive\x0d\x0aUser-Agent: GhostProxifier/1.0\x0d\x0a\x0d\x0a",
            final_host, port, final_host, port);
    }

    NetLog("[Proxy] Handshake Request: %s:%d (via %s:%d)", final_host, port, proxyIP.c_str(), proxyPort);

    NetLog("[Proxy] Sending CONNECT %s:%d", final_host, port);
    if (!SyncSend(s, request, req_len)) {
        NetLog("[Proxy] Failed to send CONNECT request to proxy (%d)", WSAGetLastError());
        return false;
    }

    std::string response;
    if (!SyncRecvResponse(s, response)) {
        NetLog("[Proxy] Failed to receive CONNECT response from proxy");
        return false;
    }

    if (response.find(" 200 ") != std::string::npos) {
        return true;
    }

    std::string err_line = response.substr(0, response.find("\r\n"));
    NetLog("[Proxy] CONNECT failed: %s", err_line.c_str());
    return false;
}

// --- CompletePendingHandshake: finish deferred HTTP CONNECT before first data send ---
bool CompletePendingHandshake(SOCKET s) {
    PendingProxy pp;
    {
        std::lock_guard<std::mutex> lock(g_PendingMutex);
        auto it = g_PendingProxySockets.find(s);
        if (it == g_PendingProxySockets.end()) return true; // no pending
        pp = std::move(it->second);
        g_PendingProxySockets.erase(it);
    }

    // Ensure the connection to the proxy initiated in hook_connect/hook_ConnectEx is finished
    fd_set wfds, efds;
    FD_ZERO(&wfds); FD_ZERO(&efds);
    FD_SET(s, &wfds); FD_SET(s, &efds);
    timeval tv = { 5, 0 }; // 5s timeout
    GlobalConfig cfg;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        cfg = g_Config;
    }

    int sel = select(0, NULL, &wfds, &efds, &tv);
    if (sel <= 0) {
        NetLog("[Proxy] Wait for proxy connection timeout/fail (sel=%d): %s:%d", sel, pp.target_ip.c_str(), pp.target_port);
        return false;
    }
    if (FD_ISSET(s, &efds)) {
        int err = 0; int len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        NetLog("[Proxy] Proxy connection error: %d on %s:%d (Target: %s:%d)", err, cfg.ProxyIP.c_str(), cfg.ProxyPort, pp.target_ip.c_str(), pp.target_port);
        return false;
    }

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt));

    DWORD t0 = GetTickCount();
    bool ok = PerformHttpConnect(s, pp.target_ip.c_str(), pp.target_port, pp.target_family, pp.domain);

    // Send any initial data from ConnectEx
    if (ok && !pp.initial_data.empty()) {
        if (!SyncSend(s, pp.initial_data.data(), (int)pp.initial_data.size())) {
            ok = false;
        }
    }

    if (ok) {
        int lat = (int)(GetTickCount() - t0);
        g_lastLatency = lat;
        g_activeConns++;
        NetLog("[Proxy] Handshake OK: %s:%d | %s (latency %dms)", pp.target_ip.c_str(), pp.target_port, pp.domain.c_str(), lat);
        std::lock_guard<std::mutex> lock(g_ProxyCompletedMutex);
        g_ProxyCompletedSockets.insert(s);
    }
    else {
        NetLog("[Proxy] Handshake FAILED: %s:%d | %s", pp.target_ip.c_str(), pp.target_port, pp.domain.c_str());
        // Put it back to avoid accidental direct connection bypass in next retry if app doesn't close socket
        std::lock_guard<std::mutex> lock(g_PendingMutex);
        g_PendingProxySockets[s] = std::move(pp);
    }
    return ok;
}
