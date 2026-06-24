#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "globals.h"

// ============================================================================
// Forward declarations from other modules
// ============================================================================
extern void LoadConfigFromEnv();
extern void InitSharedDnsCache();
extern void EnvInjectFromConfig();
extern void InstallSocketHooks();
extern void InstallDnsHooks();
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

    // Start UDP log pipeline
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    InitLogging();

    HMODULE h = GetModuleHandleA("ws2_32.dll");

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
    real_WSAIoctl = (WSAIoctl_t)GetProcAddress(h, "WSAIoctl");
    real_GetAddrInfoExW = (GetAddrInfoExW_t)GetProcAddress(h, "GetAddrInfoExW");

    // Eagerly hook ConnectEx — app may have already cached the function pointer
    // via WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER) before injection.
    // If we wait for the lazy WSAIoctl hook, cached pointers bypass us entirely.
    {
        SOCKET tmp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (tmp != INVALID_SOCKET) {
            GUID gCE = WSAID_CONNECTEX;
            LPFN_CONNECTEX pCE = NULL;
            DWORD bytes;
            if (WSAIoctl(tmp, SIO_GET_EXTENSION_FUNCTION_POINTER,
                &gCE, sizeof(gCE), &pCE, sizeof(pCE), &bytes, NULL, NULL) == 0 && pCE) {
                if (MH_CreateHook((void*)pCE, (void*)hook_ConnectEx, (void**)&real_ConnectEx) == MH_OK) {
                    NetLog("[Init] ConnectEx eagerly hooked (before app cached pointer)");
                }
            }
            closesocket(tmp);
        }
    }

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

    // Start DNS proxy thread early so g_DnsProxyPort is ready before hooks fire
    InitSharedDnsCache();
    MH_EnableHook(MH_ALL_HOOKS);
    g_Initialized = true;

    extern DWORD WINAPI DnsProxyThread(LPVOID);
    CreateThread(NULL, 0, DnsProxyThread, NULL, 0, NULL);

    // Export config to env vars so child processes inherit proxy settings.
    EnvInjectFromConfig();

    NetLog("[Init] stable core initialized.");
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
    g_InjectTick = GetTickCount();

    // Wrap initialisation in SEH to prevent crashes (e.g. in sandboxed
    // Chrome renderer processes) from killing the host.  Matches the
    // original SetupThread pattern from the initial commit.
    __try {
        SetupThreadInternal();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Silently absorb crashes — the host process must survive.
        NetLog("[Init] suppressed crash during SetupThreadInternal");
    }
}

// ============================================================================
// DllMain: entry point for DLL injection
// ============================================================================
// IMPORTANT: DllMain must return quickly — synchronous heavy initialization
// (socket creation, shared memory, MinHook) runs under the loader lock and
// will deadlock or fail in sandboxed processes (Chrome renderers, AppContainer).
// The original ghost_core.cpp spawned a thread; the shellcode calls GhostInit
// for EntryDetour.  We keep both paths: a worker thread for CreateRemoteThread,
// and the exported GhostInit (called by shellcode) runs in the first thread
// for Cygwin compatibility.
HMODULE g_hDllModule = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hDllModule = hModule;
        DisableThreadLibraryCalls(hModule);
        // Spawn worker thread — matches original SetupThread pattern.
        // For EntryDetour: the shellcode will also call GhostInit on the first
        // thread (Cygwin cygtls); the g_Initialized guard makes the second call
        // a no-op.  The worker-thread push here ensures CreateRemoteThread
        // injection also triggers full init.
        GhostInit();
    }
    return TRUE;
}
