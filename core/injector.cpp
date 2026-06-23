#include "globals.h"

// --- SetThreadContext (EntryDetour) Injection ---
// Matches proxychains-windows hookdll_main.c:404-447.
//   x64: change RCX → shellcode, leave RIP at LdrInitializeThunk.
//   x86: change Eax → shellcode, leave Eip at LdrInitializeThunk.
// LdrInitializeThunk runs FIRST, initialises ALL DLLs, then calls RCX/Eax.
// Returns true on success; false means caller should fall back to CreateRemoteThread.
bool SetThreadContextInject(HANDLE hProcess, HANDLE hThread,
                            const std::wstring& fullDllPath,
                            bool isX86, HANDLE hEvent) {
    // x86 shellcode not yet implemented — fall back to CreateRemoteThread.
    if (isX86) return false;

    static void* s_LoadLibraryW        = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    static void* s_GetProcAddress      = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    static void* s_WaitForSingleObject = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WaitForSingleObject");

#ifdef _WIN64
    // ==================================================================
    // x64 EntryDetour implementation
    // ==================================================================
    const unsigned char* shellcode  = kThreadCtxX64;
    size_t codeSize   = TC_X64_CODE_SIZE;
    size_t origOff    = TC_X64_OFF_ORIGENTRY;
    size_t llwOff     = TC_X64_OFF_LLW;
    size_t gpaOff     = TC_X64_OFF_GPA;
    size_t wfsoOff    = TC_X64_OFF_WFSO;
    size_t heventOff  = TC_X64_OFF_HEVENT;
    size_t giStrOff   = TC_X64_OFF_GHOSTINIT;
    size_t dllpathOff = TC_X64_OFF_DLLPATH;

    size_t dllPathBytes = (fullDllPath.length() + 1) * sizeof(wchar_t);
    size_t totalSize = dllpathOff + dllPathBytes;
    void* remoteMem = NULL;
    HANDLE hChildEvent = NULL;

    if (hEvent) {
        if (!DuplicateHandle(GetCurrentProcess(), hEvent, hProcess,
                             &hChildEvent, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            NetLog("[TCCtx] DuplicateHandle failed(%d), fallback", (int)GetLastError());
            return false;
        }
    }

    // Read EXE entry point from RCX
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        NetLog("[TCCtx] GetThreadContext failed(%d), fallback", (int)GetLastError());
        if (hChildEvent) CloseHandle(hChildEvent);
        return false;
    }
    DWORD64 origEntry = ctx.Rcx;
    NetLog("[TCCtx] EXE entry (RCX)=%p, RIP=%p",
           (void*)(uintptr_t)origEntry, (void*)(uintptr_t)ctx.Rip);

    remoteMem = VirtualAllocEx(hProcess, NULL, totalSize,
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        NetLog("[TCCtx] VirtualAllocEx failed(%d), fallback", (int)GetLastError());
        if (hChildEvent) CloseHandle(hChildEvent);
        return false;
    }
    NetLog("[TCCtx] Shellcode at %p, totalSize=%zu", remoteMem, totalSize);

    // Build shellcode buffer
    {
        std::vector<unsigned char> buf(totalSize);
        memcpy(buf.data(), shellcode, codeSize);

        // Copy GhostInit string
        const char* giStr = "GhostInit";
        memcpy(buf.data() + giStrOff, giStr, strlen(giStr) + 1);

        // Copy DLL path
        memcpy(buf.data() + dllpathOff, fullDllPath.c_str(), dllPathBytes);

        // Patch data pointers
        memcpy(buf.data() + origOff,   &origEntry,              8);
        memcpy(buf.data() + llwOff,    &s_LoadLibraryW,         8);
        memcpy(buf.data() + gpaOff,    &s_GetProcAddress,        8);
        memcpy(buf.data() + wfsoOff,   &s_WaitForSingleObject,  8);
        memcpy(buf.data() + heventOff, &hChildEvent,            8);

        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(hProcess, remoteMem, buf.data(), totalSize,
                                &bytesWritten) || bytesWritten != totalSize) {
            NetLog("[TCCtx] WriteProcessMemory failed(%d), fallback", (int)GetLastError());
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            if (hChildEvent) CloseHandle(hChildEvent);
            return false;
        }
    }

    // Set RCX → shellcode, leave RIP at LdrInitializeThunk.
    // LdrInitializeThunk runs first, initialises all DLLs, then calls RCX.
    ctx.Rcx = (DWORD64)(uintptr_t)remoteMem;
    if (!SetThreadContext(hThread, &ctx)) {
        NetLog("[TCCtx] SetThreadContext failed(%d), fallback", (int)GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        if (hChildEvent) CloseHandle(hChildEvent);
        return false;
    }

    NetLog("[TCCtx] RCX → shellcode %p, origEntry=%p (caller will resume)",
           remoteMem, (void*)(uintptr_t)origEntry);
    return true;
#else
    // x86 shellcode not yet implemented
    (void)hEvent;
    return false;
#endif
}

// --- Injection Core ---
bool InjectDllW(HANDLE hProcess) {
    BOOL isWow64 = FALSE;
    IsWow64Process(hProcess, &isWow64);

    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(GetModuleHandleA("ghost_core_x64.dll") ? GetModuleHandleA("ghost_core_x64.dll") : GetModuleHandleA("ghost_core_x86.dll"), dllPath, MAX_PATH);

    std::wstring wsPath = dllPath;
    size_t lastSlash = wsPath.find_last_of(L"\\/");
    std::wstring dir = (lastSlash != std::wstring::npos) ? wsPath.substr(0, lastSlash) : L".";

    std::wstring targetDll = isWow64 ? L"ghost_core_x86.dll" : L"ghost_core_x64.dll";
    std::wstring fullDllPath = dir + L"\\" + targetDll;

    // Cross-arch injection helper
    if (GetModuleHandleA("ghost_core_x64.dll") && isWow64) {
        std::wstring launcherPath = dir + L"\\ghost_launcher_x86.exe";
        DWORD pid = GetProcessId(hProcess);
        std::wstring cmd = L"\"" + launcherPath + L"\" " + std::to_wstring(pid) + L" \"" + fullDllPath + L"\"";
        std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end()); cmdBuf.push_back(0);

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            DWORD waitResult = WaitForSingleObject(pi.hProcess, 3000);
            DWORD exitCode = 1;
            bool ok = waitResult == WAIT_OBJECT_0 &&
                      GetExitCodeProcess(pi.hProcess, &exitCode) &&
                      exitCode == 0;
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            return ok;
        }
        return false;
    } else if (GetModuleHandleA("ghost_core_x86.dll") && !isWow64) {
        std::wstring launcherPath = dir + L"\\ghost_launcher_x64.exe";
        DWORD pid = GetProcessId(hProcess);
        std::wstring cmd = L"\"" + launcherPath + L"\" " + std::to_wstring(pid) + L" \"" + fullDllPath + L"\"";
        std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end()); cmdBuf.push_back(0);

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            DWORD waitResult = WaitForSingleObject(pi.hProcess, 3000);
            DWORD exitCode = 1;
            bool ok = waitResult == WAIT_OBJECT_0 &&
                      GetExitCodeProcess(pi.hProcess, &exitCode) &&
                      exitCode == 0;
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            return ok;
        }
        return false;
    }

    // Direct injection
    void* loadLibraryAddr = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    size_t pathLen = (fullDllPath.length() + 1) * sizeof(wchar_t);
    void* m = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!m) return false;
    if (!WriteProcessMemory(hProcess, m, fullDllPath.c_str(), pathLen, NULL)) {
        VirtualFreeEx(hProcess, m, 0, MEM_RELEASE);
        return false;
    }
    HANDLE t = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, m, 0, NULL);
    if (t) {
        DWORD waitResult = WaitForSingleObject(t, 1000);
        DWORD loadResult = 0;
        bool ok = waitResult == WAIT_OBJECT_0 &&
                  GetExitCodeThread(t, &loadResult) &&
                  loadResult != 0;
        CloseHandle(t);
        VirtualFreeEx(hProcess, m, 0, MEM_RELEASE);
        return ok;
    }
    VirtualFreeEx(hProcess, m, 0, MEM_RELEASE);
    return false;
}
