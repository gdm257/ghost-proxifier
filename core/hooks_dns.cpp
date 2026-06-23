#include "globals.h"

// ============================================================================
// DNS Hook Implementations
// ============================================================================

INT WSAAPI hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
    if (!g_Initialized) return real_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    PerformLazyInitialization();
    // DIAGNOSTIC: always log domain resolution to confirm hook is active
    if (pNodeName && inet_addr(pNodeName) == INADDR_NONE) {
        NetLog("[DNS-HOOK] getaddrinfo(%s) called, dnsMode=%s", pNodeName, g_Config.DnsMode.c_str());
    }
    // If not a domain name (NULL or already an IP), pass through
    if (!pNodeName || inet_addr(pNodeName) != INADDR_NONE) {
        return real_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }
    std::string domain = pNodeName;
    if (!domain.empty() && domain.back() == '.') domain.pop_back();
    std::string dnsMode;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        dnsMode = g_Config.DnsMode;
    }
    std::vector<DWORD> ips = dnsMode == "dot" ? ProxyDnsResolve(domain.c_str()) : std::vector<DWORD>();
    if (!ips.empty()) {
        // Use first resolved IP to call real function (no actual DNS happens)
        struct in_addr first_addr;
        first_addr.s_addr = ips[0];
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &first_addr, ip_str, INET_ADDRSTRLEN);
        // Record all IP-domain mappings
        std::string all_ips;
        for (DWORD ip : ips) {
            RecordIpDomainMapping(ip, domain);
            struct in_addr a; a.s_addr = ip;
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, s, INET_ADDRSTRLEN);
            if (!all_ips.empty()) all_ips += ", ";
            all_ips += s;
        }
        return real_getaddrinfo(ip_str, pServiceName, pHints, ppResult);
    }
    // Fallback to system resolver if proxy DNS fails
    NetLog("[DNS-Proxy] getaddrinfo: proxy DNS failed for %s, fallback", pNodeName);
    INT ret = real_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    if (ret == 0 && ppResult && *ppResult) {
        for (ADDRINFOA* ptr = *ppResult; ptr != NULL; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                sockaddr_in* ipv4 = (sockaddr_in*)ptr->ai_addr;
                RecordIpDomainMapping(ipv4->sin_addr.s_addr, domain);
            }
        }
    }
    return ret;
}

INT WSAAPI hook_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    if (!g_Initialized) return real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    PerformLazyInitialization();
    if (!pNodeName) {
        return real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }
    char ascii_node[1024] = { 0 };
    WideCharToMultiByte(CP_UTF8, 0, pNodeName, -1, ascii_node, sizeof(ascii_node), NULL, NULL);
    NetLog("[DNS-HOOK] GetAddrInfoW(%s) called, dnsMode=%s", ascii_node, g_Config.DnsMode.c_str());
    // If already an IP address, pass through
    if (inet_addr(ascii_node) != INADDR_NONE) {
        return real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }
    std::string domain = ascii_node;
    if (!domain.empty() && domain.back() == '.') domain.pop_back();
    std::string dnsMode;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        dnsMode = g_Config.DnsMode;
    }
    std::vector<DWORD> ips = dnsMode == "dot" ? ProxyDnsResolve(domain.c_str()) : std::vector<DWORD>();
    if (!ips.empty()) {
        struct in_addr first_addr;
        first_addr.s_addr = ips[0];
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &first_addr, ip_str, INET_ADDRSTRLEN);
        // Record all IP-domain mappings
        std::string all_ips;
        for (DWORD ip : ips) {
            RecordIpDomainMapping(ip, domain);
            struct in_addr a; a.s_addr = ip;
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, s, INET_ADDRSTRLEN);
            if (!all_ips.empty()) all_ips += ", ";
            all_ips += s;
        }
        // Convert IP string to wide and call real function
        wchar_t wip[INET_ADDRSTRLEN];
        MultiByteToWideChar(CP_UTF8, 0, ip_str, -1, wip, INET_ADDRSTRLEN);
        return real_GetAddrInfoW(wip, pServiceName, pHints, ppResult);
    }
    // Fallback to system resolver
    NetLog("[DNS-Proxy] GetAddrInfoW: proxy DNS failed for %s, fallback", ascii_node);
    INT ret = real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    if (ret == 0 && ppResult && *ppResult) {
        for (ADDRINFOW* ptr = *ppResult; ptr != NULL; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                sockaddr_in* ipv4 = (sockaddr_in*)ptr->ai_addr;
                RecordIpDomainMapping(ipv4->sin_addr.s_addr, domain);
            }
        }
    }
    return ret;
}

struct hostent* WSAAPI hook_gethostbyname(const char* name) {
    if (!g_Initialized) return real_gethostbyname(name);
    if (!name || inet_addr(name) != INADDR_NONE) {
        return real_gethostbyname(name);
    }
    std::string domain = name;
    if (!domain.empty() && domain.back() == '.') domain.pop_back();
    std::string dnsMode;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        dnsMode = g_Config.DnsMode;
    }
    NetLog("[DNS-HOOK] gethostbyname(%s) called, dnsMode=%s", name, dnsMode.c_str());
    std::vector<DWORD> ips = dnsMode == "dot" ? ProxyDnsResolve(domain.c_str()) : std::vector<DWORD>();
    if (!ips.empty()) {
        // Record all IP-domain mappings
        std::string all_ips;
        for (DWORD ip : ips) {
            RecordIpDomainMapping(ip, domain);
            struct in_addr a; a.s_addr = ip;
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, s, INET_ADDRSTRLEN);
            if (!all_ips.empty()) all_ips += ", ";
            all_ips += s;
        }
        // Call real function with IP string to get properly allocated hostent
        struct in_addr first_addr;
        first_addr.s_addr = ips[0];
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &first_addr, ip_str, INET_ADDRSTRLEN);
        return real_gethostbyname(ip_str);
    }
    // Fallback to system resolver
    NetLog("[DNS-Proxy] gethostbyname: proxy DNS failed for %s, fallback", name);
    struct hostent* ret = real_gethostbyname(name);
    if (ret) {
        for (int i = 0; ret->h_addr_list[i] != 0; ++i) {
            struct in_addr addr;
            memcpy(&addr, ret->h_addr_list[i], sizeof(struct in_addr));
            RecordIpDomainMapping(addr.s_addr, domain);
        }
    }
    return ret;
}

// --- GetAddrInfoExW hook (async DNS API, used by libcurl AsynchDNS) ---
INT WSAAPI hook_GetAddrInfoExW(PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace,
    LPGUID lpNspId, const ADDRINFOEXW* pHints, PADDRINFOEXW* ppResult,
    struct timeval* timeout, LPOVERLAPPED lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine, LPHANDLE lpNameHandle)
{
    if (!g_Initialized)
        return real_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, pHints, ppResult,
                                   timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle);
    PerformLazyInitialization();

    // Pass through if no name or already an IP
    if (!pName) {
        return real_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, pHints, ppResult,
                                   timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle);
    }
    char ascii_node[1024] = { 0 };
    WideCharToMultiByte(CP_UTF8, 0, pName, -1, ascii_node, sizeof(ascii_node), NULL, NULL);
    NetLog("[DNS-HOOK] GetAddrInfoExW(%s) called, dnsMode=%s", ascii_node, g_Config.DnsMode.c_str());

    if (inet_addr(ascii_node) != INADDR_NONE) {
        return real_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, pHints, ppResult,
                                   timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle);
    }

    std::string domain = ascii_node;
    if (!domain.empty() && domain.back() == '.') domain.pop_back();
    std::string dnsMode;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        dnsMode = g_Config.DnsMode;
    }

    std::vector<DWORD> ips = dnsMode == "dot" ? ProxyDnsResolve(domain.c_str()) : std::vector<DWORD>();
    if (!ips.empty()) {
        struct in_addr first_addr;
        first_addr.s_addr = ips[0];
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &first_addr, ip_str, INET_ADDRSTRLEN);
        // Record all IP-domain mappings
        std::string all_ips;
        for (DWORD ip : ips) {
            RecordIpDomainMapping(ip, domain);
            struct in_addr a; a.s_addr = ip;
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, s, INET_ADDRSTRLEN);
            if (!all_ips.empty()) all_ips += ", ";
            all_ips += s;
        }
        // Convert IP string to wide and call real function
        wchar_t wip[INET_ADDRSTRLEN];
        MultiByteToWideChar(CP_UTF8, 0, ip_str, -1, wip, INET_ADDRSTRLEN);
        return real_GetAddrInfoExW(wip, pServiceName, dwNameSpace, lpNspId, pHints, ppResult,
                                   timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle);
    }
    // Fallback to system resolver
    NetLog("[DNS-Proxy] GetAddrInfoExW: proxy DNS failed for %s, fallback", ascii_node);
    INT ret = real_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, pHints, ppResult,
                                  timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle);
    if (ret == 0 && ppResult && *ppResult) {
        for (ADDRINFOEXW* ptr = *ppResult; ptr != NULL; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                sockaddr_in* ipv4 = (sockaddr_in*)ptr->ai_addr;
                RecordIpDomainMapping(ipv4->sin_addr.s_addr, domain);
            }
        }
    }
    return ret;
}

// --- DnsQuery_W hook (Cygwin/MSYS2 getaddrinfo(3) internally calls this) ---
DNS_STATUS WINAPI hook_DnsQuery_W(PCWSTR pszName, WORD wType, DWORD Options,
    PIP4_ARRAY pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved)
{
    if (!g_Initialized)
        return real_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    PerformLazyInitialization();

    // Only intercept A / AAAA queries for domain names
    if (!pszName || (wType != DNS_TYPE_A && wType != DNS_TYPE_AAAA)) {
        return real_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    }

    char ascii_node[1024] = { 0 };
    WideCharToMultiByte(CP_UTF8, 0, pszName, -1, ascii_node, sizeof(ascii_node), NULL, NULL);
    NetLog("[DNS-HOOK] DnsQuery_W(%s, type=%d) called, dnsMode=%s", ascii_node, (int)wType, g_Config.DnsMode.c_str());

    if (inet_addr(ascii_node) != INADDR_NONE) {
        return real_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    }

    std::string domain = ascii_node;
    if (!domain.empty() && domain.back() == '.') domain.pop_back();
    std::string dnsMode;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        dnsMode = g_Config.DnsMode;
    }

    std::vector<DWORD> ips = dnsMode == "dot" ? ProxyDnsResolve(domain.c_str()) : std::vector<DWORD>();
    if (!ips.empty()) {
        // Record IP-domain mappings
        std::string all_ips;
        for (DWORD ip : ips) {
            RecordIpDomainMapping(ip, domain);
            struct in_addr a; a.s_addr = ip;
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, s, INET_ADDRSTRLEN);
            if (!all_ips.empty()) all_ips += ", ";
            all_ips += s;
        }
        // Construct a fake DNS_RECORD for the resolved IP.
        // Use LocalAlloc so DnsFree can free it later (DnsApi uses LocalAlloc internally).
        DWORD ip_net = ips[0];
        size_t nameLen = (wcslen(pszName) + 1) * sizeof(WCHAR);

        DNS_RECORDW* rec = (DNS_RECORDW*)LocalAlloc(LPTR, sizeof(DNS_RECORDW) + nameLen);
        if (rec) {
            rec->pNext = NULL;
            rec->pName = (PWSTR)((BYTE*)rec + sizeof(DNS_RECORDW));
            memcpy(rec->pName, pszName, nameLen);
            rec->wType = wType;
            rec->wDataLength = sizeof(DWORD);
            rec->Flags.DW = 0;
            rec->dwTtl = 300;
            rec->dwReserved = 0;
            if (wType == DNS_TYPE_A) {
                rec->Data.A.IpAddress = ip_net;
            } else {
                // AAAA: the resolved IP is IPv4; downgrade to A record
                rec->Data.A.IpAddress = ip_net;
                rec->wType = DNS_TYPE_A;
                rec->wDataLength = sizeof(DWORD);
            }
            *ppQueryResults = (PDNS_RECORD)rec;
            return ERROR_SUCCESS;
        }
        // If allocation failed, fall through to real query
    }
    // Fallback to system resolver
    NetLog("[DNS-Proxy] DnsQuery_W: proxy DNS failed for %s, fallback", ascii_node);
    DNS_STATUS ret = real_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    if (ret == ERROR_SUCCESS && ppQueryResults && *ppQueryResults) {
        for (DNS_RECORDW* r = (DNS_RECORDW*)(*ppQueryResults); r; r = r->pNext) {
            if (r->wType == DNS_TYPE_A) {
                RecordIpDomainMapping(r->Data.A.IpAddress, domain);
            }
        }
    }
    return ret;
}

// --- DnsQuery_A hook (ANSI version, same logic as DnsQuery_W) ---
DNS_STATUS WINAPI hook_DnsQuery_A(PCSTR pszName, WORD wType, DWORD Options,
    PIP4_ARRAY pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved)
{
    if (!g_Initialized)
        return real_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    PerformLazyInitialization();

    // Only intercept A / AAAA queries for domain names
    if (!pszName || (wType != DNS_TYPE_A && wType != DNS_TYPE_AAAA)) {
        return real_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    }

    NetLog("[DNS-HOOK] DnsQuery_A(%s, type=%d) called, dnsMode=%s", pszName, (int)wType, g_Config.DnsMode.c_str());

    if (inet_addr(pszName) != INADDR_NONE) {
        return real_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    }

    std::string domain = pszName;
    if (!domain.empty() && domain.back() == '.') domain.pop_back();
    std::string dnsMode;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        dnsMode = g_Config.DnsMode;
    }

    std::vector<DWORD> ips = dnsMode == "dot" ? ProxyDnsResolve(domain.c_str()) : std::vector<DWORD>();
    if (!ips.empty()) {
        std::string all_ips;
        for (DWORD ip : ips) {
            RecordIpDomainMapping(ip, domain);
            struct in_addr a; a.s_addr = ip;
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, s, INET_ADDRSTRLEN);
            if (!all_ips.empty()) all_ips += ", ";
            all_ips += s;
        }
        DWORD ip_net = ips[0];
        size_t nameLen = strlen(pszName) + 1;
        size_t wideNameBytes = nameLen * sizeof(WCHAR);

        DNS_RECORDW* rec = (DNS_RECORDW*)LocalAlloc(LPTR, sizeof(DNS_RECORDW) + wideNameBytes);
        if (rec) {
            rec->pNext = NULL;
            rec->pName = (PWSTR)((BYTE*)rec + sizeof(DNS_RECORDW));
            MultiByteToWideChar(CP_ACP, 0, pszName, -1, rec->pName, (int)nameLen);
            rec->wType = wType;
            rec->wDataLength = sizeof(DWORD);
            rec->Flags.DW = 0;
            rec->dwTtl = 300;
            rec->dwReserved = 0;
            if (wType == DNS_TYPE_A) {
                rec->Data.A.IpAddress = ip_net;
            } else {
                rec->Data.A.IpAddress = ip_net;
                rec->wType = DNS_TYPE_A;
                rec->wDataLength = sizeof(DWORD);
            }
            *ppQueryResults = (PDNS_RECORD)rec;
            return ERROR_SUCCESS;
        }
    }
    // Fallback
    NetLog("[DNS-Proxy] DnsQuery_A: proxy DNS failed for %s, fallback", pszName);
    DNS_STATUS ret = real_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    if (ret == ERROR_SUCCESS && ppQueryResults && *ppQueryResults) {
        for (DNS_RECORDW* r = (DNS_RECORDW*)(*ppQueryResults); r; r = r->pNext) {
            if (r->wType == DNS_TYPE_A) {
                RecordIpDomainMapping(r->Data.A.IpAddress, domain);
            }
        }
    }
    return ret;
}

// ============================================================================
// InstallDnsHooks: register all DNS-related MinHook hooks
// ============================================================================
void InstallDnsHooks() {
    if (real_getaddrinfo) MH_CreateHook((void*)real_getaddrinfo, (void*)hook_getaddrinfo, (void**)&real_getaddrinfo);
    if (real_GetAddrInfoW) MH_CreateHook((void*)real_GetAddrInfoW, (void*)hook_GetAddrInfoW, (void**)&real_GetAddrInfoW);
    if (real_gethostbyname) MH_CreateHook((void*)real_gethostbyname, (void*)hook_gethostbyname, (void**)&real_gethostbyname);
    if (real_GetAddrInfoExW) MH_CreateHook((void*)real_GetAddrInfoExW, (void*)hook_GetAddrInfoExW, (void**)&real_GetAddrInfoExW);
    if (real_DnsQuery_W) MH_CreateHook((void*)real_DnsQuery_W, (void*)hook_DnsQuery_W, (void**)&real_DnsQuery_W);
    if (real_DnsQuery_A) MH_CreateHook((void*)real_DnsQuery_A, (void*)hook_DnsQuery_A, (void**)&real_DnsQuery_A);
}
