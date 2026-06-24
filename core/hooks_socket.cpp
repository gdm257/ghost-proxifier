#include "globals.h"

// ============================================================================
// Socket Hook Implementations
// ============================================================================

BOOL PASCAL hook_ConnectEx(SOCKET s, const struct sockaddr* name, int namelen,
    PVOID lpSendBuffer, DWORD dwSendDataLength,
    LPDWORD lpBytesSent, LPOVERLAPPED lpOverlapped) {
    if (!g_Initialized) return real_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpBytesSent, lpOverlapped);
    PerformLazyInitialization();
    if (name && (name->sa_family == AF_INET || name->sa_family == AF_INET6)) {
        char ip[INET6_ADDRSTRLEN] = { 0 };
        int port = 0;
        bool is_local = false;
        std::string domain = "";
        if (name->sa_family == AF_INET) {
            sockaddr_in* t = (sockaddr_in*)name;
            port = ntohs(t->sin_port);
            inet_ntop(AF_INET, &(t->sin_addr), ip, INET_ADDRSTRLEN);
            GetDomainByRealIp(t->sin_addr.s_addr, domain);
            if (t->sin_addr.s_addr == inet_addr("127.0.0.1"))
                is_local = true;
        }
        else {
            sockaddr_in6* t = (sockaddr_in6*)name;
            port = ntohs(t->sin6_port);
            if (IN6_IS_ADDR_V4MAPPED(&t->sin6_addr)) {
                struct in_addr addr4;
                memcpy(&addr4, (char*)&t->sin6_addr + 12, 4);
                inet_ntop(AF_INET, &addr4, ip, INET_ADDRSTRLEN);
            }
            else {
                inet_ntop(AF_INET6, &(t->sin6_addr), ip, INET6_ADDRSTRLEN);
                if (strcmp(ip, "::1") == 0)
                    is_local = true;
            }
        }
        std::string proxyIP;
        int proxyPort;
        std::string nodeName;
        {
            std::lock_guard<std::mutex> lock(g_ConfigMutex);
            proxyIP = g_Config.ProxyIP;
            proxyPort = g_Config.ProxyPort;
            nodeName = g_Config.NodeName;
        }
        if (!is_local && port != proxyPort && nodeName != "Direct") {
            NetLog("[Proxy] ConnectEx: %s:%d | %s", ip, port, domain.c_str());
            // Save target info + initial data for deferred handshake
            PendingProxy pp = { ip, port, name->sa_family, domain, {} };
            if (lpSendBuffer && dwSendDataLength > 0) {
                pp.initial_data.assign((char*)lpSendBuffer, (char*)lpSendBuffer + dwSendDataLength);
            }
            {
                std::lock_guard<std::mutex> lock(g_PendingMutex);
                g_PendingProxySockets[s] = std::move(pp);
            }
            // Redirect ConnectEx to proxy, suppress initial data (will be sent after handshake)
            sockaddr_storage p;
            memset(&p, 0, sizeof(p));
            int p_len = 0;
            if (name->sa_family == AF_INET) {
                sockaddr_in* p4 = (sockaddr_in*)&p;
                p4->sin_family = AF_INET;
                p4->sin_addr.s_addr = inet_addr(proxyIP.c_str());
                p4->sin_port = htons(proxyPort);
                p_len = sizeof(sockaddr_in);
            }
            else {
                sockaddr_in6* p6 = (sockaddr_in6*)&p;
                p6->sin6_family = AF_INET6;
                DWORD a4 = inet_addr(proxyIP.c_str());
                if (a4 != INADDR_NONE) {
                    unsigned char* b = (unsigned char*)&p6->sin6_addr;
                    b[10] = 0xff; b[11] = 0xff;
                    memcpy(b + 12, &a4, 4);
                }
                else {
                    inet_pton(AF_INET6, proxyIP.c_str(), &p6->sin6_addr);
                }
                p6->sin6_port = htons(proxyPort);
                p_len = sizeof(sockaddr_in6);
            }

            BOOL res = real_ConnectEx(s, (const sockaddr*)&p, p_len, NULL, 0, lpBytesSent, lpOverlapped);
            if (!res && WSAGetLastError() != ERROR_IO_PENDING) {
                NetLog("[Proxy] ConnectEx to proxy failed: %d (Family: %d)", WSAGetLastError(), name->sa_family);
                return FALSE;
            }

            bool sync = false;
            { std::lock_guard<std::mutex> lock(g_ConfigMutex); sync = g_Config.SyncHandshake; }
            if (sync) {
                if (CompletePendingHandshake(s)) {
                    if (lpBytesSent) *lpBytesSent = (DWORD)pp.initial_data.size();
                    return TRUE;
                } else {
                    WSASetLastError(WSAECONNRESET);
                    return FALSE;
                }
            }
            return res;
        }
    }
    return real_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength,
        lpBytesSent, lpOverlapped);
}

int WINAPI hook_WSAConnect(SOCKET s, const sockaddr* name, int namelen,
    LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
    LPQOS lpSQOS, LPQOS lpGQOS) {
    if (!g_Initialized) return real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    if (name && (name->sa_family == AF_INET || name->sa_family == AF_INET6)) {
        char ip[INET6_ADDRSTRLEN] = { 0 };
        int port = 0;
        bool is_local = false;
        std::string domain = "";
        if (name->sa_family == AF_INET) {
            sockaddr_in* t = (sockaddr_in*)name;
            port = ntohs(t->sin_port);
            inet_ntop(AF_INET, &(t->sin_addr), ip, INET_ADDRSTRLEN);
            GetDomainByRealIp(t->sin_addr.s_addr, domain);
            if (t->sin_addr.s_addr == inet_addr("127.0.0.1"))
                is_local = true;
        }
        else {
            sockaddr_in6* t = (sockaddr_in6*)name;
            port = ntohs(t->sin6_port);
            if (IN6_IS_ADDR_V4MAPPED(&t->sin6_addr)) {
                struct in_addr addr4;
                memcpy(&addr4, (char*)&t->sin6_addr + 12, 4);
                inet_ntop(AF_INET, &addr4, ip, INET_ADDRSTRLEN);
            }
            else {
                inet_ntop(AF_INET6, &(t->sin6_addr), ip, INET6_ADDRSTRLEN);
                if (strcmp(ip, "::1") == 0)
                    is_local = true;
            }
        }
        if (IsKnownDoHServer(ip, port)) {
            NetLog("[DNS] Blocking DoH server %s:%d to force DNS fallback", ip, port);
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }

        std::string proxyIP;
        int proxyPort;
        std::string nodeName;
        {
            std::lock_guard<std::mutex> lock(g_ConfigMutex);
            proxyIP = g_Config.ProxyIP;
            proxyPort = g_Config.ProxyPort;
            nodeName = g_Config.NodeName;
        }

        if (!is_local && port != proxyPort && nodeName != "Direct") {
            // Check if socket is already connected to avoid 10056 (WSAEISCONN)
            sockaddr_storage peer;
            int plen = sizeof(peer);
            if (getpeername(s, (sockaddr*)&peer, &plen) == 0) {
                return real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
            }

            NetLog("[Proxy] WSAConnect: %s:%d (Family: %d) | %s", ip, port, name->sa_family, domain.c_str());
            // Save target info for deferred HTTP CONNECT handshake
            {
                std::lock_guard<std::mutex> lock(g_PendingMutex);
                g_PendingProxySockets[s] = { ip, port, name->sa_family, domain, {} };
            }
            // Redirect connect to proxy (keep original socket blocking mode)
            sockaddr_storage p;
            memset(&p, 0, sizeof(p));
            int p_len = 0;
            if (name->sa_family == AF_INET) {
                sockaddr_in* p4 = (sockaddr_in*)&p;
                p4->sin_family = AF_INET;
                p4->sin_addr.s_addr = inet_addr(proxyIP.c_str());
                p4->sin_port = htons(proxyPort);
                p_len = sizeof(sockaddr_in);
            }
            else {
                sockaddr_in6* p6 = (sockaddr_in6*)&p;
                p6->sin6_family = AF_INET6;
                DWORD a4 = inet_addr(proxyIP.c_str());
                if (a4 != INADDR_NONE) {
                    unsigned char* b = (unsigned char*)&p6->sin6_addr;
                    b[10] = 0xff; b[11] = 0xff;
                    memcpy(b + 12, &a4, 4);
                }
                else {
                    inet_pton(AF_INET6, proxyIP.c_str(), &p6->sin6_addr);
                }
                p6->sin6_port = htons(proxyPort);
                p_len = sizeof(sockaddr_in6);
            }

            int res = real_WSAConnect(s, (const sockaddr*)&p, p_len, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
            if (res == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
                NetLog("[Proxy] WSAConnect to proxy failed: %d (Family: %d)", WSAGetLastError(), name->sa_family);
                return res;
            }

            bool sync = false;
            { std::lock_guard<std::mutex> lock(g_ConfigMutex); sync = g_Config.SyncHandshake; }
            if (sync) {
                if (CompletePendingHandshake(s)) {
                    return 0;
                } else {
                    WSASetLastError(WSAECONNRESET);
                    return SOCKET_ERROR;
                }
            }
            return res;
        }
    }
    return real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS,
        lpGQOS);
}

int WINAPI hook_connect(SOCKET s, const sockaddr* name, int namelen) {
    if (!g_Initialized) return real_connect(s, name, namelen);
    PerformLazyInitialization();
    if (name && (name->sa_family == AF_INET || name->sa_family == AF_INET6)) {
        char ip[INET6_ADDRSTRLEN] = { 0 };
        int port = 0;
        bool is_local = false;
        std::string domain = "";

        std::string proxyIP;
        int proxyPort;
        std::string nodeName;
        int dnsProxyPort;
        {
            std::lock_guard<std::mutex> lock(g_ConfigMutex);
            proxyIP = g_Config.ProxyIP;
            proxyPort = g_Config.ProxyPort;
            nodeName = g_Config.NodeName;
            dnsProxyPort = g_Config.DnsProxyPort;
        }

        if (name->sa_family == AF_INET) {
            sockaddr_in* t = (sockaddr_in*)name;
            port = ntohs(t->sin_port);
            inet_ntop(AF_INET, &(t->sin_addr), ip, INET_ADDRSTRLEN);
            GetDomainByRealIp(t->sin_addr.s_addr, domain);
            int type = 0;
            int optlen = sizeof(type);
            getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&type, &optlen);
            if (type == SOCK_DGRAM && port == 53 && dnsProxyPort > 0) {
                sockaddr_in l = *t;
                l.sin_addr.s_addr = inet_addr("127.0.0.1");
                l.sin_port = htons(dnsProxyPort);
                return real_connect(s, (sockaddr*)&l, sizeof(l));
            }
            // Block QUIC (UDP 443) to force Chrome/Edge fallback to TCP
            if (type == SOCK_DGRAM && port == 443) {
                NetLog("[QUIC] Blocking UDP 443 to %s:%d to force TCP fallback", ip, port);
                WSASetLastError(WSAECONNREFUSED);
                return SOCKET_ERROR;
            }
            if (t->sin_addr.s_addr == inet_addr("127.0.0.1"))
                is_local = true;
        }
        else {
            sockaddr_in6* t = (sockaddr_in6*)name;
            port = ntohs(t->sin6_port);
            if (IN6_IS_ADDR_V4MAPPED(&t->sin6_addr)) {
                struct in_addr addr4;
                memcpy(&addr4, (char*)&t->sin6_addr + 12, 4);
                inet_ntop(AF_INET, &addr4, ip, INET_ADDRSTRLEN);
            }
            else {
                inet_ntop(AF_INET6, &(t->sin6_addr), ip, INET6_ADDRSTRLEN);
                if (strcmp(ip, "::1") == 0)
                    is_local = true;
            }
        }
        if (IsKnownDoHServer(ip, port)) {
            NetLog("[DNS] Blocking DoH server %s:%d to force DNS fallback", ip, port);
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }
        if (!is_local && port != proxyPort && nodeName != "Direct") {
            NetLog("[Proxy] connect: %s:%d (Family: %d) | %s", ip, port, name->sa_family, domain.c_str());
            // Save target info for deferred HTTP CONNECT handshake
            {
                std::lock_guard<std::mutex> lock(g_PendingMutex);
                g_PendingProxySockets[s] = { ip, port, name->sa_family, domain, {} };
            }
            // Redirect connect to proxy (keep original socket blocking mode)
            sockaddr_storage p;
            memset(&p, 0, sizeof(p));
            int p_len = 0;
            if (name->sa_family == AF_INET) {
                sockaddr_in* p4 = (sockaddr_in*)&p;
                p4->sin_family = AF_INET;
                p4->sin_addr.s_addr = inet_addr(proxyIP.c_str());
                p4->sin_port = htons(proxyPort);
                p_len = sizeof(sockaddr_in);
            }
            else {
                sockaddr_in6* p6 = (sockaddr_in6*)&p;
                p6->sin6_family = AF_INET6;
                DWORD a4 = inet_addr(proxyIP.c_str());
                if (a4 != INADDR_NONE) {
                    unsigned char* b = (unsigned char*)&p6->sin6_addr;
                    b[10] = 0xff; b[11] = 0xff;
                    memcpy(b + 12, &a4, 4);
                }
                else {
                    inet_pton(AF_INET6, proxyIP.c_str(), &p6->sin6_addr);
                }
                p6->sin6_port = htons(proxyPort);
                p_len = sizeof(sockaddr_in6);
            }

            int res = real_connect(s, (const sockaddr*)&p, p_len);
            if (res == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
                NetLog("[Proxy] connect to proxy failed: %d (Family: %d)", WSAGetLastError(), name->sa_family);
                return res;
            }

            bool sync = false;
            { std::lock_guard<std::mutex> lock(g_ConfigMutex); sync = g_Config.SyncHandshake; }
            if (sync) {
                if (CompletePendingHandshake(s)) {
                    return 0;
                } else {
                    WSASetLastError(WSAECONNRESET);
                    return SOCKET_ERROR;
                }
            }
            return res;
        }
    }
    return real_connect(s, name, namelen);
}

// --- Lazy handshake send hooks ---
int WINAPI hook_send(SOCKET s, const char* buf, int len, int flags) {
    if (!g_Initialized) return real_send(s, buf, len, flags);
    if (!CompletePendingHandshake(s)) {
        WSASetLastError(WSAECONNRESET);
        return SOCKET_ERROR;
    }
    int ret = real_send(s, buf, len, flags);
    return ret;
}

int WINAPI hook_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!g_Initialized) return real_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
    if (!CompletePendingHandshake(s)) {
        WSASetLastError(WSAECONNRESET);
        return SOCKET_ERROR;
    }
    return real_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

int WINAPI hook_recv(SOCKET s, char* buf, int len, int flags) {
    if (!g_Initialized) return real_recv(s, buf, len, flags);
    if (!CompletePendingHandshake(s)) {
        WSASetLastError(WSAECONNRESET);
        return SOCKET_ERROR;
    }
    int ret = real_recv(s, buf, len, flags);
    return ret;
}

int WINAPI hook_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!g_Initialized) return real_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    if (!CompletePendingHandshake(s)) {
        WSASetLastError(WSAECONNRESET);
        return SOCKET_ERROR;
    }
    return real_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}

int WINAPI hook_sendto(SOCKET s, const char* buf, int len, int flags,
    const struct sockaddr* to, int tolen) {
    if (!g_Initialized) return real_sendto(s, buf, len, flags, to, tolen);
    PerformLazyInitialization();
    int dnsProxyPort;
    std::string dnsMode;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        dnsProxyPort = g_Config.DnsProxyPort;
        dnsMode = g_Config.DnsMode;
    }
    if (to && (to->sa_family == AF_INET || to->sa_family == AF_INET6) && dnsProxyPort > 0 && dnsMode == "dot") {
        int target_port = 0;
        if (to->sa_family == AF_INET) target_port = ntohs(((sockaddr_in*)to)->sin_port);
        else target_port = ntohs(((sockaddr_in6*)to)->sin6_port);

        // Block QUIC (UDP 443) to force Chrome/Edge fallback to TCP
        if (target_port == 443) {
            NetLog("[QUIC] hook_sendto: Blocking UDP 443 to force TCP fallback");
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }

        if (target_port == 53) {
            sockaddr_storage l;
            memset(&l, 0, sizeof(l));
            int l_len = 0;
            if (to->sa_family == AF_INET) {
                sockaddr_in* l4 = (sockaddr_in*)&l;
                l4->sin_family = AF_INET;
                l4->sin_addr.s_addr = inet_addr("127.0.0.1");
                l4->sin_port = htons(dnsProxyPort);
                l_len = sizeof(sockaddr_in);
            }
            else {
                sockaddr_in6* l6 = (sockaddr_in6*)&l;
                l6->sin6_family = AF_INET6;
                unsigned char* b = (unsigned char*)&l6->sin6_addr;
                b[10] = 0xff; b[11] = 0xff;
                b[12] = 127; b[13] = 0; b[14] = 0; b[15] = 1;
                l6->sin6_port = htons(dnsProxyPort);
                l_len = sizeof(sockaddr_in6);
            }
            NetLog("[DNS] hook_sendto: Translated Family:%d to 127.0.0.1:%d", to->sa_family, dnsProxyPort);
            return real_sendto(s, buf, len, flags, (sockaddr*)&l, l_len);
        }
    }
    return real_sendto(s, buf, len, flags, to, tolen);
}

int WINAPI hook_WSASendTo(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo,
    int iTolen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!g_Initialized) return real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
    PerformLazyInitialization();
    int dnsProxyPort;
    std::string dnsMode;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        dnsProxyPort = g_Config.DnsProxyPort;
        dnsMode = g_Config.DnsMode;
    }
    if (lpTo && lpTo->sa_family == AF_INET && dnsProxyPort > 0 && dnsMode == "dot") {
        int target_port = ntohs(((sockaddr_in*)lpTo)->sin_port);

        // Block QUIC (UDP 443) to force Chrome/Edge fallback to TCP
        if (target_port == 443) {
            NetLog("[QUIC] hook_WSASendTo: Blocking UDP 443 to force TCP fallback");
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }

        if (target_port == 53) {
            sockaddr_in l = *(sockaddr_in*)lpTo;
            l.sin_addr.s_addr = inet_addr("127.0.0.1");
            l.sin_port = htons(dnsProxyPort);
            NetLog("[DNS] hook_WSASendTo: Translated to 127.0.0.1:%d", dnsProxyPort);
            return real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                dwFlags, (sockaddr*)&l, sizeof(l), lpOverlapped,
                lpCompletionRoutine);
        }
    }
    return real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
        dwFlags, lpTo, iTolen, lpOverlapped,
        lpCompletionRoutine);
}

int WINAPI hook_recvfrom(SOCKET s, char* buf, int len, int flags,
    struct sockaddr* from, int* fromlen) {
    if (!g_Initialized) return real_recvfrom(s, buf, len, flags, from, fromlen);
    int ret = real_recvfrom(s, buf, len, flags, from, fromlen);
    if (ret > 0 && from && fromlen && *fromlen >= sizeof(sockaddr_in)) {
        sockaddr_in* f = (sockaddr_in*)from;
        int dnsProxyPort;
        std::string dnsIP;
        int dnsPort;
        {
            std::lock_guard<std::mutex> lock(g_ConfigMutex);
            dnsProxyPort = g_Config.DnsProxyPort;
            dnsIP = g_Config.DnsIP;
            dnsPort = g_Config.DnsPort;
        }
        if (f->sin_family == AF_INET &&
            f->sin_addr.s_addr == inet_addr("127.0.0.1") && dnsProxyPort > 0 &&
            ntohs(f->sin_port) == dnsProxyPort) {
            f->sin_addr.s_addr = inet_addr(dnsIP.c_str());
            f->sin_port = htons(dnsPort);

            std::string ips = "";
            if (ret >= 12) {
                int a_off = 12;
                unsigned short q_cnt = ntohs(*(unsigned short*)(buf + 4));
                std::string query_domain = "";
                for (int i = 0; i < q_cnt && a_off < ret; i++) {
                    std::string d = GetDnsName(buf, a_off, ret);
                    if (i == 0) query_domain = d;
                    a_off += 4;
                }
                unsigned short a_cnt = ntohs(*(unsigned short*)(buf + 6));
                for (int i = 0; i < a_cnt && a_off < ret; i++) {
                    GetDnsName(buf, a_off, ret);
                    if (a_off + 10 <= ret) {
                        unsigned short type = ntohs(*(unsigned short*)(buf + a_off));
                        unsigned short dlen = ntohs(*(unsigned short*)(buf + a_off + 8));
                        if (type == 1 && dlen == 4 && a_off + 10 + 4 <= ret) {
                            char ip[16];
                            unsigned char* p = (unsigned char*)(buf + a_off + 10);
                            sprintf_s(ip, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
                            if (!ips.empty())
                                ips += ", ";
                            ips += ip;
                            if (!query_domain.empty()) {
                                DWORD net_ip;
                                memcpy(&net_ip, p, 4);
                                RecordIpDomainMapping(net_ip, query_domain);
                            }
                        }
                        a_off += 10 + dlen;
                    }
                    else
                        break;
                }
            }
            NetLog("[DNS] hook_recvfrom: Translated 127.0.0.1:%d -> %s:%d (len: "
                "%d) A_Records: [%s]",
                dnsProxyPort, dnsIP.c_str(), dnsPort, ret, ips.c_str());
        }
    }
    return ret;
}

int WINAPI hook_WSARecvFrom(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom,
    LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!g_Initialized) return real_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    int ret = real_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
        lpFlags, lpFrom, lpFromlen, lpOverlapped,
        lpCompletionRoutine);
    if (ret == 0 && lpFrom && lpFromlen && *lpFromlen >= sizeof(sockaddr_in)) {
        sockaddr_in* f = (sockaddr_in*)lpFrom;
        int dnsProxyPort;
        std::string dnsIP;
        int dnsPort;
        {
            std::lock_guard<std::mutex> lock(g_ConfigMutex);
            dnsProxyPort = g_Config.DnsProxyPort;
            dnsIP = g_Config.DnsIP;
            dnsPort = g_Config.DnsPort;
        }
        if (f->sin_family == AF_INET &&
            f->sin_addr.s_addr == inet_addr("127.0.0.1") && dnsProxyPort > 0 &&
            ntohs(f->sin_port) == dnsProxyPort) {
            f->sin_addr.s_addr = inet_addr(dnsIP.c_str());
            f->sin_port = htons(dnsPort);
            DWORD bytes = lpNumberOfBytesRecvd ? *lpNumberOfBytesRecvd : 0;

            std::string ips = "";
            if (bytes >= 12 && dwBufferCount > 0 && lpBuffers[0].buf) {
                char* buf = lpBuffers[0].buf;
                int a_off = 12;
                unsigned short q_cnt = ntohs(*(unsigned short*)(buf + 4));
                std::string query_domain = "";
                for (int i = 0; i < q_cnt && a_off < bytes; i++) {
                    std::string d = GetDnsName(buf, a_off, bytes);
                    if (i == 0) query_domain = d;
                    a_off += 4;
                }
                unsigned short a_cnt = ntohs(*(unsigned short*)(buf + 6));
                for (int i = 0; i < a_cnt && a_off < bytes; i++) {
                    GetDnsName(buf, a_off, bytes);
                    if (a_off + 10 <= bytes) {
                        unsigned short type = ntohs(*(unsigned short*)(buf + a_off));
                        unsigned short dlen = ntohs(*(unsigned short*)(buf + a_off + 8));
                        if (type == 1 && dlen == 4 && a_off + 10 + 4 <= bytes) {
                            char ip[16];
                            unsigned char* p = (unsigned char*)(buf + a_off + 10);
                            sprintf_s(ip, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
                            if (!ips.empty())
                                ips += ", ";
                            ips += ip;
                            if (!query_domain.empty()) {
                                DWORD net_ip;
                                memcpy(&net_ip, p, 4);
                                RecordIpDomainMapping(net_ip, query_domain);
                            }
                        }
                        a_off += 10 + dlen;
                    }
                    else
                        break;
                }
            }
            NetLog("[DNS] hook_WSARecvFrom: Translated 127.0.0.1:%d -> %s:%d "
                "(len: %d) A_Records: [%s]",
                dnsProxyPort, dnsIP.c_str(), dnsPort, bytes, ips.c_str());
        }
    }
    return ret;
}

int WINAPI hook_closesocket(SOCKET s) {
    if (!g_Initialized) return real_closesocket ? real_closesocket(s) : 0;
    {
        std::lock_guard<std::mutex> lock(g_PendingMutex);
        g_PendingProxySockets.erase(s);
    }
    return real_closesocket(s);
}

int WINAPI hook_WSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!real_WSAIoctl) return SOCKET_ERROR;
    int ret = real_WSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);

    if (ret == 0 && dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER && lpvInBuffer && cbInBuffer >= sizeof(GUID)) {
        GUID* g = (GUID*)lpvInBuffer;
        GUID gConnectEx = WSAID_CONNECTEX;
        if (memcmp(g, &gConnectEx, sizeof(GUID)) == 0 && lpvOutBuffer && cbOutBuffer >= sizeof(void*)) {
            void* pCE = *(void**)lpvOutBuffer;
            if (pCE && pCE != (void*)hook_ConnectEx) {
                if (MH_CreateHook(pCE, (void*)hook_ConnectEx, (void**)&real_ConnectEx) == MH_OK) {
                    MH_EnableHook(pCE);
                    *(void**)lpvOutBuffer = (void*)hook_ConnectEx;
                    NetLog("[Init] ConnectEx lazily hooked via WSAIoctl.");
                }
            }
        }
    }
    return ret;
}

// ============================================================================
// InstallSocketHooks: register all socket-related MinHook hooks
// ============================================================================
void InstallSocketHooks() {
    // connect/ConnectEx hooks
    MH_CreateHook((void*)real_connect, (void*)hook_connect, (void**)&real_connect);
    if (real_WSAConnect) MH_CreateHook((void*)real_WSAConnect, (void*)hook_WSAConnect, (void**)&real_WSAConnect);

    // send/recv hooks
    MH_CreateHook((void*)real_send, (void*)hook_send, (void**)&real_send);
    MH_CreateHook((void*)real_recv, (void*)hook_recv, (void**)&real_recv);
    if (real_WSASend) MH_CreateHook((void*)real_WSASend, (void*)hook_WSASend, (void**)&real_WSASend);
    if (real_WSARecv) MH_CreateHook((void*)real_WSARecv, (void*)hook_WSARecv, (void**)&real_WSARecv);

    // sendto/recvfrom hooks
    MH_CreateHook((void*)real_sendto, (void*)hook_sendto, (void**)&real_sendto);
    MH_CreateHook((void*)real_WSASendTo, (void*)hook_WSASendTo, (void**)&real_WSASendTo);
    if (real_recvfrom) MH_CreateHook((void*)real_recvfrom, (void*)hook_recvfrom, (void**)&real_recvfrom);
    if (real_WSARecvFrom) MH_CreateHook((void*)real_WSARecvFrom, (void*)hook_WSARecvFrom, (void**)&real_WSARecvFrom);

    // close hook
    if (real_closesocket) MH_CreateHook((void*)real_closesocket, (void*)hook_closesocket, (void**)&real_closesocket);

    // WSAIoctl (for lazy ConnectEx hook)
    if (real_WSAIoctl) MH_CreateHook((void*)real_WSAIoctl, (void*)hook_WSAIoctl, (void**)&real_WSAIoctl);
}
