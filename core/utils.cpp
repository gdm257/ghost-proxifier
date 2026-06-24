#include "globals.h"

// --- IP-Domain Mapping ---
void RecordIpDomainMapping(DWORD net_ip, const std::string& domain) {
    if (domain.empty()) return;
    std::lock_guard<std::mutex> lock(g_IpMapMutex);
    g_IpToDomainMap[net_ip] = domain;
}

bool GetDomainByRealIp(DWORD net_ip, std::string& domain) {
    std::lock_guard<std::mutex> lock(g_IpMapMutex);
    auto it = g_IpToDomainMap.find(net_ip);
    if (it != g_IpToDomainMap.end()) {
        domain = it->second;
        return true;
    }
    return false;
}

// --- UDP Log Pipeline ---
SOCKET g_LogSocket  = INVALID_SOCKET;
DWORD  g_InjectTick = 0;
int    g_LogPort    = 0;

static CRITICAL_SECTION s_LogLock;
static bool s_LogLockInit = false;

void InitLogging() {
    if (g_LogPort <= 0) return;
    InitializeCriticalSection(&s_LogLock);
    s_LogLockInit = true;

    g_LogSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_LogSocket == INVALID_SOCKET) return;

    // Non-blocking so a full kernel buffer never stalls a hook
    u_long mode = 1;
    ioctlsocket(g_LogSocket, FIONBIO, &mode);

    // Connected UDP — use send() instead of sendto()
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((u_short)g_LogPort);
    connect(g_LogSocket, (sockaddr*)&addr, sizeof(addr));
}

void NetLog(const char* format, ...) {
    if (g_LogSocket == INVALID_SOCKET || !s_LogLockInit) return;

    // Relative timestamp since injection
    DWORD elapsed = GetTickCount() - g_InjectTick;
    unsigned int sec  = elapsed / 1000;
    unsigned int msec = elapsed % 1000;

    // Format the message body first
    char body[1024];
    va_list args;
    va_start(args, format);
    vsprintf_s(body, format, args);
    va_end(args);

    // Extract TAG from the formatted body: first [...] token
    const char* tagStart = NULL;
    int tagLen = 0;
    const char* afterTag = body;
    if (body[0] == '[') {
        tagStart = body;
        const char* p = body + 1;
        while (*p && *p != ']') p++;
        if (*p == ']') {
            tagLen = (int)(p - tagStart + 1);
            afterTag = p + 1;
            while (*afterTag == ' ' || *afterTag == ':') afterTag++;
        }
    }

    // Assemble packet: "[REL_TS] [PID:TID] TAG message"
    char pkt[1400];
    int pktLen;
    if (tagStart && tagLen > 0) {
        pktLen = sprintf_s(pkt, sizeof(pkt),
            "[%03u.%03u] [%lu:%lu] %.*s %s",
            sec, msec,
            GetCurrentProcessId(), GetCurrentThreadId(),
            tagLen, tagStart, afterTag);
    } else {
        pktLen = sprintf_s(pkt, sizeof(pkt),
            "[%03u.%03u] [%lu:%lu] [LOG] %s",
            sec, msec,
            GetCurrentProcessId(), GetCurrentThreadId(),
            body);
    }

    // Best-effort non-blocking send
    if (pktLen > 0 && pktLen < (int)sizeof(pkt)) {
        EnterCriticalSection(&s_LogLock);
        send(g_LogSocket, pkt, pktLen, 0);
        LeaveCriticalSection(&s_LogLock);
    }
}

// --- BreakExistingConnections: force-close existing TCP connections ---
void BreakExistingConnections() {
    DWORD pid = GetCurrentProcessId();

    std::string proxyIP;
    int proxyPort;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        proxyIP = g_Config.ProxyIP;
        proxyPort = g_Config.ProxyPort;
    }
    DWORD proxyAddr = inet_addr(proxyIP.c_str());

    // Get required buffer size for IPv4 TCP connections
    ULONG size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;

    std::vector<BYTE> buf(size);
    PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)buf.data();
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return;

    int broken = 0;
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID& row = table->table[i];
        if (row.dwOwningPid != pid) continue;

        DWORD localhost = inet_addr("127.0.0.1");

        // Skip localhost connections (internal comms)
        if (row.dwRemoteAddr == localhost) continue;
        // Skip connections already to proxy
        if (row.dwRemoteAddr == proxyAddr && ntohs((u_short)row.dwRemotePort) == (u_short)proxyPort) continue;
        // Skip listening sockets
        if (row.dwState == MIB_TCP_STATE_LISTEN) continue;
        // Skip already closed
        if (row.dwState == MIB_TCP_STATE_CLOSED) continue;
        // Skip time_wait (already half-closed)
        if (row.dwState == MIB_TCP_STATE_TIME_WAIT) continue;

        MIB_TCPROW delRow;
        delRow.dwState = MIB_TCP_STATE_DELETE_TCB; // 12 — force TCB teardown
        delRow.dwLocalAddr = row.dwLocalAddr;
        delRow.dwLocalPort = row.dwLocalPort;
        delRow.dwRemoteAddr = row.dwRemoteAddr;
        delRow.dwRemotePort = row.dwRemotePort;

        if (SetTcpEntry(&delRow) == NO_ERROR) {
            struct in_addr a; a.s_addr = row.dwRemoteAddr;
            NetLog("[Init] Broken existing connection: %s:%d",
                inet_ntoa(a), ntohs((u_short)row.dwRemotePort));
            broken++;
        }
    }

    if (broken > 0) {
        NetLog("[Init] Broken %d existing TCP connections to force proxy path.", broken);
    }
}

// --- GetParentProcessId: enumerates the parent PID via NtQueryInformationProcess ---
DWORD GetParentProcessId() {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (!h) return 0;

    typedef long NTSTATUS;
    typedef struct _PROCESS_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        void* PebBaseAddress;
        ULONG_PTR AffinityMask;
        long BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION;

    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, int, void*, ULONG, PULONG);
    static pNtQueryInformationProcess NtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    DWORD pPid = 0;
    if (NtQueryInfo) {
        PROCESS_BASIC_INFORMATION pbi;
        if (NtQueryInfo(h, 0, &pbi, sizeof(pbi), NULL) >= 0) {
            pPid = (DWORD)pbi.InheritedFromUniqueProcessId;
        }
    }
    CloseHandle(h);
    return pPid;
}

// --- SyncSend: blocking send over a possibly non-blocking socket ---
bool SyncSend(SOCKET s, const char* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = real_send(s, buf + sent, len - sent, 0);
        if (n > 0)
            sent += n;
        else if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(s, &wfds);
            timeval tv = { 5, 0 };
            if (select(0, NULL, &wfds, NULL, &tv) <= 0)
                return false;
        }
        else
            return false;
    }
    return true;
}

// --- SyncRecvResponse: reads HTTP response line-by-line ---
bool SyncRecvResponse(SOCKET s, std::string& resp) {
    char c;
    while (resp.find("\x0d\x0a\x0d\x0a") == std::string::npos) {
        // Read 1 byte at a time to avoid consuming application data (like SSH banners)
        // that follow immediately after the HTTP response.
        int n = real_recv(s, &c, 1, 0);
        if (n > 0) {
            resp += c;
        }
        else if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(s, &rfds);
            timeval tv = { 5, 0 };
            if (select(0, &rfds, NULL, NULL, &tv) <= 0) {
                return false;
            }
        }
        else {
            return false;
        }
        if (resp.size() > 2048) return false;
    }
    return true;
}

// --- IsKnownDoHServer: blocks known DoH endpoints to force DNS-over-TCP ---
bool IsKnownDoHServer(const char* ip, int port) {
    if (strcmp(ip, "8.8.8.8") == 0) return true;
    if (strcmp(ip, "8.8.4.4") == 0) return true;
    if (strcmp(ip, "1.1.1.1") == 0) return true;
    if (strcmp(ip, "1.0.0.1") == 0) return true;
    if (strcmp(ip, "2001:4860:4860::8888") == 0) return true;
    if (strcmp(ip, "2001:4860:4860::8844") == 0) return true;
    if (strcmp(ip, "2606:4700:4700::1111") == 0) return true;
    if (strcmp(ip, "2606:4700:4700::1001") == 0) return true;
    return false;
}

// --- GetDnsName: DNS name decompression ---
std::string GetDnsName(const char* buf, int& offset, int total_len) {
    std::string name = "";
    int pos = offset;
    int jumps = 0;
    int first_jump = -1;
    while (pos < total_len) {
        unsigned char len = (unsigned char)buf[pos++];
        if (len == 0)
            break;
        if ((len & 0xC0) == 0xC0) {
            if (pos >= total_len)
                break;
            if (first_jump == -1)
                first_jump = pos + 1;
            pos = ((len & 0x3F) << 8) | (unsigned char)buf[pos];
            if (++jumps > 10)
                break;
            continue;
        }
        if (pos + len > total_len)
            break;
        for (int i = 0; i < len; i++)
            name += buf[pos++];
        name += ".";
    }
    offset = (first_jump != -1) ? first_jump : pos;
    return name;
}

// --- Global variable definitions ---
std::unordered_map<DWORD, std::string> g_IpToDomainMap;
std::mutex g_IpMapMutex;
