#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <fstream>
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <ctime>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#include <windns.h>
#include "MinHook.h"

// --- NT Definitions ---
typedef LONG NTSTATUS;
#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef int(WINAPI* connect_t)(SOCKET s, const sockaddr* name, int namelen);
typedef int(WINAPI* WSAConnect_t)(SOCKET s, const sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
typedef BOOL(PASCAL* ConnectEx_t)(SOCKET s, const struct sockaddr* name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpBytesSent, LPOVERLAPPED lpOverlapped);
typedef int(WINAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int(WINAPI* recv_t)(SOCKET s, char* buf, int len, int flags);
typedef int(WINAPI* sendto_t)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
typedef int(WINAPI* WSASendTo_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int(WINAPI* recvfrom_t)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
typedef int(WINAPI* WSARecvFrom_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int(WINAPI* WSASend_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int(WINAPI* WSARecv_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int(WINAPI* closesocket_t)(SOCKET s);
typedef INT(WSAAPI* getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef INT(WSAAPI* GetAddrInfoW_t)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef struct hostent* (WSAAPI* gethostbyname_t)(const char*);
typedef BOOL(WINAPI* WSAGetOverlappedResult_t)(SOCKET s, LPWSAOVERLAPPED lpOverlapped, LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpdwFlags);
typedef BOOL(WINAPI* GetQueuedCompletionStatus_t)(HANDLE CompletionPort, LPDWORD lpNumberOfBytesTransferred, PULONG_PTR lpCompletionKey, LPOVERLAPPED* lpOverlapped, DWORD dwMilliseconds);
typedef BOOL(WINAPI* GetQueuedCompletionStatusEx_t)(HANDLE CompletionPort, LPOVERLAPPED_ENTRY lpCompletionPortEntries, ULONG ulCount, PULONG ulNumEntriesRemoved, DWORD dwMilliseconds, BOOL fAlertable);
typedef BOOL(WINAPI* CreateProcessW_t)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL(WINAPI* CreateProcessAsUserW_t)(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL(WINAPI* CreateProcessInternalW_t)(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE phNewToken);
typedef NTSTATUS(NTAPI* NtCreateUserProcess_t)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, PVOID ProcessObjectAttributes, PVOID ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, PVOID CreateInfo, PVOID AttributeList);
typedef int(WINAPI* WSAIoctl_t)(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef INT (WSAAPI* GetAddrInfoExW_t)(PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace, LPGUID lpNspId, const ADDRINFOEXW* pHints, PADDRINFOEXW* ppResult, struct timeval* timeout, LPOVERLAPPED lpOverlapped, LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine, LPHANDLE lpNameHandle);
typedef DNS_STATUS (WINAPI* DnsQuery_W_t)(PCWSTR pszName, WORD wType, DWORD Options, PIP4_ARRAY pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved);
typedef DNS_STATUS (WINAPI* DnsQuery_A_t)(PCSTR pszName, WORD wType, DWORD Options, PIP4_ARRAY pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved);
typedef void (WINAPI* DnsFree_t)(PVOID pData, DNS_FREE_TYPE FreeType);

// --- Shellcode byte arrays ---
extern const unsigned char kThreadCtxX64[];
extern const unsigned char kThreadCtxX86[];

// Shellcode offsets for x64
#define TC_X64_CODE_SIZE        0x57
#define TC_X64_OFF_ORIGENTRY    0x58
#define TC_X64_OFF_LLW          0x60
#define TC_X64_OFF_GPA          0x68
#define TC_X64_OFF_WFSO         0x70
#define TC_X64_OFF_HEVENT       0x78
#define TC_X64_OFF_GHOSTINIT    0x80
#define TC_X64_OFF_DLLPATH      0x8A

// --- Original function pointers (resolved in SetupThreadInternal) ---
extern connect_t                 real_connect;
extern WSAConnect_t              real_WSAConnect;
extern ConnectEx_t               real_ConnectEx;
extern send_t                    real_send;
extern recv_t                    real_recv;
extern sendto_t                  real_sendto;
extern WSASendTo_t               real_WSASendTo;
extern recvfrom_t                real_recvfrom;
extern WSARecvFrom_t             real_WSARecvFrom;
extern WSASend_t                 real_WSASend;
extern WSARecv_t                 real_WSARecv;
extern closesocket_t             real_closesocket;
extern getaddrinfo_t             real_getaddrinfo;
extern GetAddrInfoW_t            real_GetAddrInfoW;
extern gethostbyname_t           real_gethostbyname;
extern GetAddrInfoExW_t          real_GetAddrInfoExW;
extern DnsQuery_W_t              real_DnsQuery_W;
extern DnsQuery_A_t              real_DnsQuery_A;
extern DnsFree_t                 real_DnsFree;
extern WSAGetOverlappedResult_t  real_WSAGetOverlappedResult;
extern GetQueuedCompletionStatus_t   real_GetQueuedCompletionStatus;
extern GetQueuedCompletionStatusEx_t real_GetQueuedCompletionStatusEx;
extern CreateProcessW_t          real_CreateProcessW;
extern CreateProcessA_t          real_CreateProcessA;
extern CreateProcessAsUserW_t    real_CreateProcessAsUserW;
extern CreateProcessInternalW_t  real_CreateProcessInternalW;
extern NtCreateUserProcess_t     real_NtCreateUserProcess;
extern WSAIoctl_t                real_WSAIoctl;

// --- Global state ---
extern SOCKET g_DnsProxyUdpSocket;

extern std::atomic<uint64_t> g_sentBytes;
extern std::atomic<uint64_t> g_recvBytes;
extern std::atomic<int> g_lastLatency;
extern SOCKET g_CommonUdpSocket;
extern std::mutex g_UdpMutex;
extern std::unordered_map<DWORD, std::string> g_IpToDomainMap;
extern std::mutex g_IpMapMutex;

// --- Thread-safe Config ---
struct GlobalConfig {
    std::string NodeName = "Direct";
    std::string ProxyIP = "127.0.0.1";
    int ProxyPort = 2080;
    std::string DnsIP = "8.8.8.8";
    int DnsPort = 53;
    std::string DnsMode = "system";
    int DnsProxyPort = 0;
    bool SyncHandshake = false;
};
extern GlobalConfig g_Config;
extern std::mutex g_ConfigMutex;
extern char g_CurrentGuid[64];
extern time_t g_InjectTime;
extern std::atomic<bool> g_Initialized;
extern std::atomic<bool> g_ProxyEngineInitialized;
extern std::mutex g_EngineInitMutex;
extern std::atomic<int> g_DnsProxyPort;

enum OverlappedOp { OP_SEND, OP_RECV };
#define OVERLAPPED_BUCKETS 64
extern std::unordered_map<LPWSAOVERLAPPED, OverlappedOp> g_PendingOverlappedBuckets[OVERLAPPED_BUCKETS];
extern std::mutex g_OverlappedMutexes[OVERLAPPED_BUCKETS];

// --- Pending Proxy (Lazy Handshake) ---
struct PendingProxy {
    std::string target_ip;
    int target_port;
    int target_family;
    std::string domain;
    std::vector<char> initial_data; // ConnectEx send buffer
};
extern std::unordered_map<SOCKET, PendingProxy> g_PendingProxySockets;
extern std::mutex g_PendingMutex;

// --- DNS over TCP Worker ---
struct DnsReq {
    sockaddr_in client_addr;
    int client_len;
    char buf[2048];
    int len;
};

// --- Proxy DNS Resolution ---
extern std::atomic<unsigned short> g_DnsTxId;

// --- DNS Cache (shared memory, cross-process) ---
#define SHARED_DNS_CACHE_ENTRIES 256
#define SHARED_DNS_CACHE_MAGIC   0x47444E54  // "DNSG" v2 — bumped for domain field
#define SHARED_DNS_CACHE_TTL_MS  1200000      // 20 minutes

struct SharedDnsCacheEntry {
    DWORD domain_hash;   // FNV-1a hash (0 = empty slot)
    DWORD ips[4];        // up to 4 IPv4 addresses (network byte order)
    DWORD expire_tick;   // GetTickCount() based expiration
    DWORD access_tick;   // for LRU eviction
    char  domain[48];    // domain name string (null-terminated, for dump tool readability)
};

struct SharedDnsCacheHeader {
    DWORD magic;
    DWORD entry_count;
    DWORD max_ttl_ms;
    DWORD padding;
};

extern HANDLE g_hSharedCacheMapping;
extern SharedDnsCacheEntry* g_pSharedCache;
extern HANDLE g_hSharedCacheMutex;
extern SharedDnsCacheHeader* g_pSharedHeader;

// --- Per-process DNS cache ---
struct DnsCacheEntry {
    std::vector<DWORD> ips;
    DWORD expire_tick;
};
extern std::unordered_map<std::string, DnsCacheEntry> g_DnsCache;
extern std::mutex g_DnsCacheMutex;

// --- DNS Connection Pool ---
#define DNS_POOL_MAX 16
#define DNS_POOL_IDLE_MS (60 * 1000)

struct DnsPoolConn {
    SOCKET sock;
    DWORD last_used;
};
extern std::vector<DnsPoolConn> g_DnsPool;
extern std::mutex g_DnsPoolMutex;

// ============================================================================
// Function declarations (cross-file usage)
// ============================================================================

// utils.cpp
int GetBucketIndex(LPWSAOVERLAPPED ov);
void RegisterOverlapped(LPWSAOVERLAPPED ov, OverlappedOp op);
void RecordIpDomainMapping(DWORD net_ip, const std::string& domain);
bool GetDomainByRealIp(DWORD net_ip, std::string& domain);
void NetLog(const char* format, ...);
DWORD GetParentProcessId();
void InitUdpSocket();
bool SyncSend(SOCKET s, const char* buf, int len);
bool SyncRecvResponse(SOCKET s, std::string& resp);
bool IsKnownDoHServer(const char* ip, int port);
std::string GetDnsName(const char* buf, int& offset, int total_len);

// config.cpp
void PerformLazyInitialization();
void PerformLazyInitializationInternal();
DWORD WINAPI DelayedInitThread(LPVOID);
void LoadConfigFromEnv();
void EnvInjectFromConfig();
void StartStats();
void NetConfigHandshake();

// proxy.cpp
bool CompletePendingHandshake(SOCKET s);
bool PerformHttpConnect(SOCKET s, const char* ip_str, int port, int family, const std::string& domain);

// dns.cpp
DWORD WINAPI DnsProxyThread(LPVOID p);
DWORD WINAPI DnsWorkerThread(LPVOID param);
int BuildDnsQuery(const char* domain, char* buf, int bufSize);
bool DnsQueryOnSocket(SOCKET s, const char* query, int qlen, std::vector<DWORD>& results);
std::vector<DWORD> ProxyDnsResolve(const char* domain);

// dns_cache.cpp
DWORD HashDomainForCache(const char* domain);
void InitSharedDnsCache();
bool SharedDnsCacheLookup(const char* domain, std::vector<DWORD>& results);
void SharedDnsCacheInsert(const char* domain, const std::vector<DWORD>& ips);

// dns_pool.cpp
SOCKET CreateDnsConn();
SOCKET AcquireDnsConn();
void ReleaseDnsConn(SOCKET s);

// stats.cpp
DWORD WINAPI StatsThread(LPVOID);

// injector.cpp
bool SetThreadContextInject(HANDLE hProcess, HANDLE hThread,
                            const std::wstring& fullDllPath,
                            bool isX86, HANDLE hEvent);
bool InjectDllW(HANDLE hProcess);
bool InjectIntoChild(HANDLE hProcess, HANDLE hThread, HANDLE hEvent);

// hooks_socket.cpp
void InstallSocketHooks();

// hooks_dns.cpp
void InstallDnsHooks();

// hooks_process.cpp
void InstallProcessHooks();

// --- External hook functions (referenced by Install*Hooks and WSAIoctl) ---

// hooks_socket.cpp
BOOL PASCAL hook_ConnectEx(SOCKET s, const struct sockaddr* name, int namelen,
    PVOID lpSendBuffer, DWORD dwSendDataLength,
    LPDWORD lpBytesSent, LPOVERLAPPED lpOverlapped);
int WINAPI hook_WSAConnect(SOCKET s, const sockaddr* name, int namelen,
    LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
    LPQOS lpSQOS, LPQOS lpGQOS);
int WINAPI hook_connect(SOCKET s, const sockaddr* name, int namelen);
int WINAPI hook_send(SOCKET s, const char* buf, int len, int flags);
int WINAPI hook_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WINAPI hook_recv(SOCKET s, char* buf, int len, int flags);
int WINAPI hook_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WINAPI hook_sendto(SOCKET s, const char* buf, int len, int flags,
    const struct sockaddr* to, int tolen);
int WINAPI hook_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo,
    int iTolen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WINAPI hook_recvfrom(SOCKET s, char* buf, int len, int flags,
    struct sockaddr* from, int* fromlen);
int WINAPI hook_WSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom,
    LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WINAPI hook_closesocket(SOCKET s);
int WINAPI hook_WSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer,
    DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
BOOL WINAPI hook_WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED lpOverlapped,
    LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpdwFlags);
BOOL WINAPI hook_GetQueuedCompletionStatus(HANDLE CompletionPort,
    LPDWORD lpNumberOfBytesTransferred, PULONG_PTR lpCompletionKey,
    LPOVERLAPPED* lpOverlapped, DWORD dwMilliseconds);
BOOL WINAPI hook_GetQueuedCompletionStatusEx(HANDLE CompletionPort,
    LPOVERLAPPED_ENTRY lpCompletionPortEntries, ULONG ulCount,
    PULONG ulNumEntriesRemoved, DWORD dwMilliseconds, BOOL fAlertable);

// hooks_dns.cpp
INT WSAAPI hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName,
    const ADDRINFOA* pHints, PADDRINFOA* ppResult);
INT WSAAPI hook_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName,
    const ADDRINFOW* pHints, PADDRINFOW* ppResult);
INT WSAAPI hook_GetAddrInfoExW(PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace,
    LPGUID lpNspId, const ADDRINFOEXW* pHints, PADDRINFOEXW* ppResult,
    struct timeval* timeout, LPOVERLAPPED lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine, LPHANDLE lpNameHandle);
struct hostent* WSAAPI hook_gethostbyname(const char* name);
DNS_STATUS WINAPI hook_DnsQuery_W(PCWSTR pszName, WORD wType, DWORD Options,
    PIP4_ARRAY pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved);
DNS_STATUS WINAPI hook_DnsQuery_A(PCSTR pszName, WORD wType, DWORD Options,
    PIP4_ARRAY pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved);

// hooks_process.cpp
BOOL WINAPI hook_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
BOOL WINAPI hook_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
