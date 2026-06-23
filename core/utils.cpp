#include "globals.h"

// --- Bucket-based overlapped I/O tracking ---
int GetBucketIndex(LPWSAOVERLAPPED ov) {
    return ((uintptr_t)ov >> 4) % OVERLAPPED_BUCKETS;
}

void RegisterOverlapped(LPWSAOVERLAPPED ov, OverlappedOp op) {
    if (!ov) return;
    int idx = GetBucketIndex(ov);
    std::lock_guard<std::mutex> lock(g_OverlappedMutexes[idx]);
    g_PendingOverlappedBuckets[idx][ov] = op;
}

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

// --- NetLog: UDP-based logging to port 45002 (consumed by CLI) ---
void NetLog(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsprintf_s(buffer, format, args);
    va_end(args);

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(45002);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[1200];
    int len = sprintf_s(line, "[%02d:%02d:%02d.%03d][%04d] %s", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentProcessId(), buffer);

    std::lock_guard<std::mutex> lock(g_UdpMutex);
    if (g_CommonUdpSocket != INVALID_SOCKET) {
        sendto(g_CommonUdpSocket, line, len, 0, (sockaddr*)&addr, sizeof(addr));
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

// --- InitUdpSocket: creates the shared UDP socket for config updates and logging ---
void InitUdpSocket() {
    std::lock_guard<std::mutex> lock(g_UdpMutex);
    if (g_CommonUdpSocket != INVALID_SOCKET) return;
    g_CommonUdpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    DWORD timeout = 500;
    setsockopt(g_CommonUdpSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
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
                NetLog("[Proxy] SyncRecvResponse timeout");
                return false;
            }
        }
        else {
            NetLog("[Proxy] SyncRecvResponse failed: %d (n=%d)", WSAGetLastError(), n);
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
SOCKET g_CommonUdpSocket = INVALID_SOCKET;
std::mutex g_UdpMutex;
std::unordered_map<DWORD, std::string> g_IpToDomainMap;
std::mutex g_IpMapMutex;
std::unordered_map<LPWSAOVERLAPPED, OverlappedOp> g_PendingOverlappedBuckets[OVERLAPPED_BUCKETS];
std::mutex g_OverlappedMutexes[OVERLAPPED_BUCKETS];
