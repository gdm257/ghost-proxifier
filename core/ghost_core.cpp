#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "globals.h"

// ============================================================================
// Forward declarations from other modules
// ============================================================================
extern void LoadConfigFromEnv();
extern void InitSharedDnsCache();
extern void InitUdpSocket();
extern void StartStats();
extern void EnvInjectFromConfig();
extern void InstallSocketHooks();
extern void InstallDnsHooks();
extern void InstallProcessHooks();
extern void NetLog(const char* format, ...);

// ============================================================================
// Real function pointers (resolved in SetupThreadInternal)
// ============================================================================
connect_t                 real_connect = NULL;
WSAConnect_t              real_WSAConnect = NULL;
ConnectEx_t               real_ConnectEx = NULL;
send_t                    real_send = NULL;
recv_t                    real_recv = NULL;
sendto_t                  real_sendto = NULL;
WSASendTo_t               real_WSASendTo = NULL;
recvfrom_t                real_recvfrom = NULL;
WSARecvFrom_t             real_WSARecvFrom = NULL;
WSASend_t                 real_WSASend = NULL;
WSARecv_t                 real_WSARecv = NULL;
closesocket_t             real_closesocket = NULL;
getaddrinfo_t             real_getaddrinfo = NULL;
GetAddrInfoW_t            real_GetAddrInfoW = NULL;
gethostbyname_t           real_gethostbyname = NULL;
GetAddrInfoExW_t          real_GetAddrInfoExW = NULL;
DnsQuery_W_t              real_DnsQuery_W = NULL;
DnsQuery_A_t              real_DnsQuery_A = NULL;
DnsFree_t                 real_DnsFree = NULL;
WSAGetOverlappedResult_t  real_WSAGetOverlappedResult = NULL;
GetQueuedCompletionStatus_t   real_GetQueuedCompletionStatus = NULL;
GetQueuedCompletionStatusEx_t real_GetQueuedCompletionStatusEx = NULL;
CreateProcessW_t          real_CreateProcessW = NULL;
CreateProcessA_t          real_CreateProcessA = NULL;
CreateProcessAsUserW_t    real_CreateProcessAsUserW = NULL;
CreateProcessInternalW_t  real_CreateProcessInternalW = NULL;
NtCreateUserProcess_t     real_NtCreateUserProcess = NULL;
WSAIoctl_t                real_WSAIoctl = NULL;

// ============================================================================
// SetupThreadInternal: resolve function pointers, install MinHook hooks
// ============================================================================
void SetupThreadInternal() {
    LoadConfigFromEnv();
    MH_Initialize();
    HMODULE h = GetModuleHandleA("ws2_32.dll");
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    HMODULE hKBase = GetModuleHandleA("kernelbase.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    // Function Pointers
    real_CreateProcessW = (CreateProcessW_t)GetProcAddress(hK32, "CreateProcessW");
    real_CreateProcessA = (CreateProcessA_t)GetProcAddress(hK32, "CreateProcessA");
    real_NtCreateUserProcess = (NtCreateUserProcess_t)GetProcAddress(hNtdll, "NtCreateUserProcess");

    // Network hooks
    real_send = (send_t)GetProcAddress(h, "send");
    real_recv = (recv_t)GetProcAddress(h, "recv");
    real_sendto = (sendto_t)GetProcAddress(h, "sendto");
    real_WSASendTo = (WSASendTo_t)GetProcAddress(h, "WSASendTo");
    real_recvfrom = (recvfrom_t)GetProcAddress(h, "recvfrom");
    real_WSARecvFrom = (WSARecvFrom_t)GetProcAddress(h, "WSARecvFrom");
    real_WSARecv = (WSARecv_t)GetProcAddress(h, "WSARecv");
    real_closesocket = (closesocket_t)GetProcAddress(h, "closesocket");
    real_connect = (connect_t)GetProcAddress(h, "connect");
    real_WSAConnect = (WSAConnect_t)GetProcAddress(h, "WSAConnect");
    real_getaddrinfo = (getaddrinfo_t)GetProcAddress(h, "getaddrinfo");
    real_GetAddrInfoW = (GetAddrInfoW_t)GetProcAddress(h, "GetAddrInfoW");
    real_gethostbyname = (gethostbyname_t)GetProcAddress(h, "gethostbyname");
    real_WSASend = (WSASend_t)GetProcAddress(h, "WSASend");
    real_WSAGetOverlappedResult = (WSAGetOverlappedResult_t)GetProcAddress(h, "WSAGetOverlappedResult");
    real_WSAIoctl = (WSAIoctl_t)GetProcAddress(h, "WSAIoctl");
    real_GetAddrInfoExW = (GetAddrInfoExW_t)GetProcAddress(h, "GetAddrInfoExW");

    // Load dnsapi.dll for DnsQuery hooks (Cygwin/MSYS2 getaddrinfo internally uses these)
    HMODULE hDnsapi = LoadLibraryA("dnsapi.dll");
    if (hDnsapi) {
        real_DnsQuery_W = (DnsQuery_W_t)GetProcAddress(hDnsapi, "DnsQuery_W");
        real_DnsQuery_A = (DnsQuery_A_t)GetProcAddress(hDnsapi, "DnsQuery_A");
        real_DnsFree = (DnsFree_t)GetProcAddress(hDnsapi, "DnsFree");
    }

    // Install hooks by category
    InstallSocketHooks();
    InstallDnsHooks();

    // GetQueuedCompletionStatus hooks (kernel32)
    if (hK32) {
        real_GetQueuedCompletionStatus = (GetQueuedCompletionStatus_t)GetProcAddress(hK32, "GetQueuedCompletionStatus");
        if (real_GetQueuedCompletionStatus) MH_CreateHook((void*)real_GetQueuedCompletionStatus, (void*)hook_GetQueuedCompletionStatus, (void**)&real_GetQueuedCompletionStatus);
        real_GetQueuedCompletionStatusEx = (GetQueuedCompletionStatusEx_t)GetProcAddress(hK32, "GetQueuedCompletionStatusEx");
        if (real_GetQueuedCompletionStatusEx) MH_CreateHook((void*)real_GetQueuedCompletionStatusEx, (void*)hook_GetQueuedCompletionStatusEx, (void**)&real_GetQueuedCompletionStatusEx);
    }

    // Process hooks
    InstallProcessHooks();

    StartStats();
    InitSharedDnsCache();
    InitUdpSocket();
    MH_EnableHook(MH_ALL_HOOKS);
    g_Initialized = true;

    // Export config to env vars so child processes inherit proxy settings.
    EnvInjectFromConfig();

    NetLog("[Init] stable core initialized (EntryDetour mode).");

    // Signal that hooks are ready
    wchar_t eventName[64];
    swprintf_s(eventName, L"Global\\GhostCoreReady_%u", (unsigned int)GetCurrentProcessId());
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, eventName);
    if (hEvent) {
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }
}

// ============================================================================
// GhostInit: called by EntryDetour shellcode or DllMain fallback
// ============================================================================
// GhostInit is called by the EntryDetour shellcode via GetProcAddress AFTER
// LoadLibraryW returns — matching proxychains-windows' InitHook() approach.
// It runs in the FIRST thread (the entry-point thread), which is critical for
// Cygwin: Cygwin's cygtls is only correctly set up for the thread that receives
// DLL_PROCESS_ATTACH.  Calling MH_EnableHook from a CreateRemoteThread worker
// thread corrupts cygtls and causes SIGSEGV (proxychains-windows DEVNOTES.md).
//
// Also called from DllMain as a fallback for CreateRemoteThread injection.
// The g_Initialized guard prevents double-initialisation when both paths fire.
extern "C" __declspec(dllexport) void WINAPI GhostInit() {
    if (g_Initialized) return;

    GetEnvironmentVariableA("GHOST_GUID", g_CurrentGuid, sizeof(g_CurrentGuid));
    g_InjectTime = time(nullptr);
    SetupThreadInternal();  // MH_EnableHook runs here
}

// ============================================================================
// DllMain: entry point for DLL injection
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // For EntryDetour (SetThreadContext): GhostInit runs here in the first
        // thread, then the shellcode calls it again (no-op, g_Initialized=true).
        // For CreateRemoteThread fallback: GhostInit only runs here.
        GhostInit();
    }
    return TRUE;
}
