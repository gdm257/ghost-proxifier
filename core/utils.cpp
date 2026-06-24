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

// --- CloseExistingQuicSockets: force-close pre-existing QUIC UDP sockets ---
// Chrome/Edge cache QUIC sessions; our connect/sendto hooks block NEW QUIC,
// but pre-injection QUIC sockets persist.  We enumerate the current process's
// handles via NtQuerySystemInformation, find UDP sockets connected to port
// 443, and close them so the browser falls back to TCP immediately.
void BreakExistingConnections() {
    DWORD pid = GetCurrentProcessId();

    // -- NtQuerySystemInformation boilerplate (ntdll.dll) --
    typedef long NTSTATUS;
    #define SystemHandleInformation 16

    typedef struct _SYSTEM_HANDLE {
        ULONG  ProcessId;
        BYTE   ObjectTypeNumber;
        BYTE   Flags;
        USHORT Handle;
        PVOID  Object;
        ACCESS_MASK GrantedAccess;
    } SYSTEM_HANDLE, *PSYSTEM_HANDLE;

    typedef struct _SYSTEM_HANDLE_INFORMATION {
        ULONG         Count;
        SYSTEM_HANDLE Handles[1];
    } SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

    typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
    static pNtQuerySystemInformation NtQuerySysInfo = NULL;
    if (!NtQuerySysInfo) {
        NtQuerySysInfo = (pNtQuerySystemInformation)
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    }
    if (!NtQuerySysInfo) return;

    // Query handle list with retry on buffer growth
    ULONG bufSize = 0x100000; // 1 MB — Chrome can have tens of thousands of handles
    std::vector<BYTE> buf(bufSize);
    NTSTATUS st;
    for (int retry = 0; retry < 3; retry++) {
        ULONG needed = 0;
        st = NtQuerySysInfo(SystemHandleInformation, buf.data(), bufSize, &needed);
        if (st == 0) break;
        if (needed > bufSize) bufSize = needed + 0x10000;
        else bufSize *= 2;
        buf.resize(bufSize);
    }
    if (st != 0) return;

    PSYSTEM_HANDLE_INFORMATION info = (PSYSTEM_HANDLE_INFORMATION)buf.data();
    int closed = 0;

    for (ULONG i = 0; i < info->Count; i++) {
        if (info->Handles[i].ProcessId != pid) continue;

        SOCKET s = (SOCKET)(ULONG_PTR)info->Handles[i].Handle;

        int type = 0, optlen = sizeof(type);
        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&type, &optlen) != 0)
            continue;                 // not a socket, or invalid handle
        if (type != SOCK_DGRAM)       // we only care about UDP
            continue;

        sockaddr_storage peer;
        int plen = sizeof(peer);
        if (getpeername(s, (sockaddr*)&peer, &plen) != 0)
            continue;                 // not connected

        int port = 0;
        if (peer.ss_family == AF_INET)
            port = ntohs(((sockaddr_in*)&peer)->sin_port);
        else if (peer.ss_family == AF_INET6)
            port = ntohs(((sockaddr_in6*)&peer)->sin6_port);
        if (port != 443) continue;

        // Found a connected QUIC socket — close it
        char ip[INET6_ADDRSTRLEN] = "";
        if (peer.ss_family == AF_INET)
            inet_ntop(AF_INET, &((sockaddr_in*)&peer)->sin_addr, ip, sizeof(ip));
        else
            inet_ntop(AF_INET6, &((sockaddr_in6*)&peer)->sin6_addr, ip, sizeof(ip));

        closesocket(s);
        NetLog("[Init] Closed existing QUIC socket: %s:443", ip);
        closed++;
    }

    if (closed > 0) {
        NetLog("[Init] Closed %d existing QUIC socket(s) — browser will fall back to TCP.", closed);
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
