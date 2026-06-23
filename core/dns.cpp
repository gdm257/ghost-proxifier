#include "globals.h"

// --- Proxy DNS Resolution ---
std::atomic<unsigned short> g_DnsTxId{ 1 };
SOCKET g_DnsProxyUdpSocket = INVALID_SOCKET;

// --- DNS over TCP Worker ---
DWORD WINAPI DnsWorkerThread(LPVOID param) {
    if (!g_Initialized) { delete (DnsReq*)param; return 0; }
    DnsReq* req = (DnsReq*)param;
    SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock == INVALID_SOCKET) {
        delete req;
        return 0;
    }
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

    sockaddr_in p_addr;
    p_addr.sin_family = AF_INET;
    p_addr.sin_addr.s_addr = inet_addr(proxyIP.c_str());
    p_addr.sin_port = htons(proxyPort);
    if (real_connect &&
        real_connect(tcp_sock, (sockaddr*)&p_addr, sizeof(p_addr)) == 0) {
        int opt = 1;
        setsockopt(tcp_sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt));
        std::string empty_domain = "";
        if (PerformHttpConnect(tcp_sock, dnsIP.c_str(), dnsPort, AF_INET, empty_domain)) {
            unsigned short len_n = htons((unsigned short)req->len);
            real_send(tcp_sock, (char*)&len_n, 2, 0);
            real_send(tcp_sock, req->buf, req->len, 0);

            unsigned short rlen_n = 0;
            fd_set rfds; FD_ZERO(&rfds); FD_SET(tcp_sock, &rfds);
            timeval tv = { 5, 0 };
            if (select(0, &rfds, NULL, NULL, &tv) > 0 && real_recv(tcp_sock, (char*)&rlen_n, 2, 0) == 2) {
                int rlen = ntohs(rlen_n);
                if (rlen > 0 && rlen <= 2048) {
                    std::vector<char> resp_buf(rlen);
                    int rvd = 0;
                    while (rvd < rlen) {
                        FD_ZERO(&rfds); FD_SET(tcp_sock, &rfds);
                        tv = { 5, 0 };
                        if (select(0, &rfds, NULL, NULL, &tv) <= 0) break;

                        int c = real_recv(tcp_sock, resp_buf.data() + rvd, rlen - rvd, 0);
                        if (c <= 0)
                            break;
                        rvd += c;
                    }
                    if (rvd == rlen) {
                        real_sendto(g_DnsProxyUdpSocket, resp_buf.data(), rlen, 0,
                            (sockaddr*)&req->client_addr, req->client_len);
                        int q_off = 12;
                        std::string domain = GetDnsName(req->buf, q_off, req->len);
                        std::string ips = "";
                        int a_off = 12;
                        unsigned short q_cnt =
                            ntohs(*(unsigned short*)(resp_buf.data() + 4));
                        for (int i = 0; i < q_cnt; i++) {
                            GetDnsName(resp_buf.data(), a_off, rlen);
                            a_off += 4;
                        }
                        unsigned short a_cnt =
                            ntohs(*(unsigned short*)(resp_buf.data() + 6));
                        std::string ipv6s = "";
                        for (int i = 0; i < a_cnt; i++) {
                            GetDnsName(resp_buf.data(), a_off, rlen);
                            unsigned short type =
                                ntohs(*(unsigned short*)(resp_buf.data() + a_off));
                            unsigned short dlen =
                                ntohs(*(unsigned short*)(resp_buf.data() + a_off + 8));
                            if (type == 1 && dlen == 4 && a_off + 10 + 4 <= rlen) {
                                char ip[16];
                                unsigned char* p =
                                    (unsigned char*)(resp_buf.data() + a_off + 10);
                                sprintf_s(ip, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
                                if (!ips.empty())
                                    ips += ", ";
                                ips += ip;
                                // Record IP-domain mapping for connect hook
                                if (!domain.empty()) {
                                    std::string clean_domain = domain;
                                    if (!clean_domain.empty() && clean_domain.back() == '.') clean_domain.pop_back();
                                    DWORD net_ip;
                                    memcpy(&net_ip, p, 4);
                                    RecordIpDomainMapping(net_ip, clean_domain);
                                }
                            }
                            else if (type == 28 && dlen == 16 && a_off + 10 + 16 <= rlen) {
                                char ip6[INET6_ADDRSTRLEN];
                                inet_ntop(AF_INET6, resp_buf.data() + a_off + 10, ip6, INET6_ADDRSTRLEN);
                                if (!ipv6s.empty()) ipv6s += ", ";
                                ipv6s += ip6;
                            }
                            a_off += 10 + dlen;
                        }

                        if (!ips.empty())
                            NetLog("[DNS] Query: %s -> A: [%s]", domain.c_str(), ips.c_str());
                        if (!ipv6s.empty())
                            NetLog("[DNS] Query: %s -> AAAA: [%s]", domain.c_str(), ipv6s.c_str());

                    }
                }
            }
        }
    }
    closesocket(tcp_sock);
    delete req;
    return 0;
}

// --- DnsProxyThread: local DNS proxy that forwards UDP DNS to TCP-over-proxy ---
DWORD WINAPI DnsProxyThread(LPVOID p) {
    while (!g_Initialized) Sleep(100);
    g_DnsProxyUdpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_DnsProxyUdpSocket == INVALID_SOCKET)
        return 0;
    sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = htons(0);
    bind(g_DnsProxyUdpSocket, (sockaddr*)&a, sizeof(a));
    int l = sizeof(a);
    getsockname(g_DnsProxyUdpSocket, (sockaddr*)&a, &l);
    g_DnsProxyPort = ntohs(a.sin_port);
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        g_Config.DnsProxyPort = g_DnsProxyPort;
    }
    NetLog("[DNS] Local Gateway Ready on 127.0.0.1:%d", g_DnsProxyPort.load());
    char buf[2048];
    sockaddr_in c_addr;
    int c_len = sizeof(c_addr);
    while (true) {
        int n = real_recvfrom(g_DnsProxyUdpSocket, buf, 2048, 0,
            (sockaddr*)&c_addr, &c_len);
        if (n > 0) {
            DnsReq* r = new DnsReq();
            r->client_addr = c_addr;
            r->client_len = c_len;
            memcpy(r->buf, buf, n);
            r->len = n;
            CreateThread(NULL, 0, DnsWorkerThread, r, 0, NULL);
        }
    }
    return 0;
}

// --- BuildDnsQuery: creates a DNS A-record query packet ---
int BuildDnsQuery(const char* domain, char* buf, int bufSize) {
    if (!domain || bufSize < 512) return 0;
    unsigned short txid = g_DnsTxId.fetch_add(1);
    buf[0] = (txid >> 8) & 0xFF;
    buf[1] = txid & 0xFF;
    buf[2] = 0x01; buf[3] = 0x00; // flags: recursion desired
    buf[4] = 0x00; buf[5] = 0x01; // 1 question
    buf[6] = buf[7] = buf[8] = buf[9] = buf[10] = buf[11] = 0;
    int pos = 12;
    const char* p = domain;
    while (*p) {
        const char* dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len == 0) { p++; continue; }
        if (pos + 1 + len >= bufSize) return 0;
        buf[pos++] = (char)len;
        memcpy(buf + pos, p, len);
        pos += len;
        if (dot) p = dot + 1; else break;
    }
    buf[pos++] = 0; // end of name
    buf[pos++] = 0x00; buf[pos++] = 0x01; // type A
    buf[pos++] = 0x00; buf[pos++] = 0x01; // class IN
    return pos;
}

// --- DnsQueryOnSocket: performs DNS query over an already-connected socket ---
bool DnsQueryOnSocket(SOCKET s, const char* query, int qlen, std::vector<DWORD>& results) {
    unsigned short len_n = htons((unsigned short)qlen);
    if (!SyncSend(s, (char*)&len_n, 2) || !SyncSend(s, query, qlen))
        return false;

    unsigned short rlen_n = 0;
    fd_set rfds; FD_ZERO(&rfds); FD_SET(s, &rfds);
    timeval tv = { 5, 0 };
    if (select(0, &rfds, NULL, NULL, &tv) <= 0) return false;
    if (real_recv(s, (char*)&rlen_n, 2, 0) != 2)
        return false;

    int rlen = ntohs(rlen_n);
    if (rlen <= 0 || rlen > 2048)
        return false;

    std::vector<char> resp(rlen);
    int rvd = 0;
    while (rvd < rlen) {
        FD_ZERO(&rfds); FD_SET(s, &rfds);
        tv = { 5, 0 };
        if (select(0, &rfds, NULL, NULL, &tv) <= 0) return false;

        int c = real_recv(s, resp.data() + rvd, rlen - rvd, 0);
        if (c <= 0) return false;
        rvd += c;
    }
    // Parse A records
    int a_off = 12;
    unsigned short q_cnt = ntohs(*(unsigned short*)(resp.data() + 4));
    for (int i = 0; i < q_cnt && a_off < rlen; i++) {
        GetDnsName(resp.data(), a_off, rlen);
        a_off += 4;
    }
    unsigned short a_cnt = ntohs(*(unsigned short*)(resp.data() + 6));
    for (int i = 0; i < a_cnt && a_off < rlen; i++) {
        GetDnsName(resp.data(), a_off, rlen);
        if (a_off + 10 <= rlen) {
            unsigned short type = ntohs(*(unsigned short*)(resp.data() + a_off));
            unsigned short dlen = ntohs(*(unsigned short*)(resp.data() + a_off + 8));
            if (type == 1 && dlen == 4 && a_off + 10 + 4 <= rlen) {
                DWORD ip;
                memcpy(&ip, resp.data() + a_off + 10, 4);
                results.push_back(ip);
            }
            a_off += 10 + dlen;
        }
        else break;
    }
    return true;
}

// Format resolved IPs into a comma-separated string for unified DNS log output.
// The format "domain -> [ip1, ip2]" is parsed by the UI's DNS intercept table.
static std::string FormatDnsResultLog(const char* domain, const std::vector<DWORD>& ips) {
    std::string s = "resolved: ";
    s += domain;
    s += " -> [";
    for (size_t i = 0; i < ips.size(); i++) {
        if (i > 0) s += ", ";
        struct in_addr a; a.s_addr = ips[i];
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, buf, sizeof(buf));
        s += buf;
    }
    s += "] (";
    s += std::to_string(ips.size());
    s += " IPs)";
    return s;
}

// --- ProxyDnsResolve: full DNS resolution pipeline (cache -> network) ---
std::vector<DWORD> ProxyDnsResolve(const char* domain) {
    std::vector<DWORD> results;
    if (!domain) return results;

    // 1. Init shared memory cache (lazy, first call per process)
    InitSharedDnsCache();

    // 2. Check shared cache (cross-process, mutex-protected)
    if (SharedDnsCacheLookup(domain, results)) {
        // Also warm the per-process cache so subsequent lookups skip the mutex
        if (!results.empty()) {
            std::lock_guard<std::mutex> lock(g_DnsCacheMutex);
            g_DnsCache[domain] = { results, GetTickCount() + SHARED_DNS_CACHE_TTL_MS };
        }
        NetLog("[DNS-Proxy] %s", FormatDnsResultLog(domain, results).c_str());
        return results;
    }

    // 3. Check per-process cache (fast path, no mutex across processes)
    {
        std::lock_guard<std::mutex> lock(g_DnsCacheMutex);
        auto it = g_DnsCache.find(domain);
        if (it != g_DnsCache.end() && GetTickCount() < it->second.expire_tick) {
            results = it->second.ips;
            NetLog("[DNS-Cache] HIT: %s (%d IPs)", domain, (int)results.size());
            NetLog("[DNS-Proxy] %s", FormatDnsResultLog(domain, results).c_str());
            return results;
        }
    }
    // Cache miss — will need network resolution
    NetLog("[DNS-Cache] MISS: %s", domain);

    // 4. Network resolution — DNS over TCP through proxy
    char query[512];
    int qlen = BuildDnsQuery(domain, query, sizeof(query));
    if (qlen == 0) return results;

    // Try pooled connection first
    SOCKET s = AcquireDnsConn();
    if (s != INVALID_SOCKET) {
        if (DnsQueryOnSocket(s, query, qlen, results)) {
            ReleaseDnsConn(s); // return to pool
        }
        else {
            closesocket(s); // dead, try fresh
            s = CreateDnsConn();
            if (s != INVALID_SOCKET) {
                if (DnsQueryOnSocket(s, query, qlen, results))
                    ReleaseDnsConn(s);
                else
                    closesocket(s);
            }
        }
    }
    else {
        // Pool empty, create new
        s = CreateDnsConn();
        if (s != INVALID_SOCKET) {
            if (DnsQueryOnSocket(s, query, qlen, results))
                ReleaseDnsConn(s);
            else
                closesocket(s);
        }
    }

    // 5. Store results in both caches, print unified log
    if (!results.empty()) {
        {
            std::lock_guard<std::mutex> lock(g_DnsCacheMutex);
            g_DnsCache[domain] = { results, GetTickCount() + SHARED_DNS_CACHE_TTL_MS };
        }
        SharedDnsCacheInsert(domain, results);
        NetLog("[DNS-Proxy] %s", FormatDnsResultLog(domain, results).c_str());
    }
    return results;
}
