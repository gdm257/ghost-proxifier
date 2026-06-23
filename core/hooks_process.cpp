#include "globals.h"

// --- Child Process Injection ---
// Prefers SetThreadContext (EntryDetour) which runs GhostInit in the FIRST thread.
// Falls back to CreateRemoteThread if SetThreadContext fails or for x86 targets.
bool InjectIntoChild(HANDLE hProcess, HANDLE hThread, HANDLE hEvent) {
    DWORD pid = GetProcessId(hProcess);
    BOOL isWow64 = FALSE;
    IsWow64Process(hProcess, &isWow64);

    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(GetModuleHandleA("ghost_core_x64.dll") ? GetModuleHandleA("ghost_core_x64.dll") : GetModuleHandleA("ghost_core_x86.dll"), dllPath, MAX_PATH);

    std::wstring wsPath = dllPath;
    size_t lastSlash = wsPath.find_last_of(L"\\/");
    std::wstring dir = (lastSlash != std::wstring::npos) ? wsPath.substr(0, lastSlash) : L".";
    std::wstring targetDll = isWow64 ? L"ghost_core_x86.dll" : L"ghost_core_x64.dll";
    std::wstring fullDllPath = dir + L"\\" + targetDll;

    wchar_t processPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameExW(hProcess, NULL, processPath, MAX_PATH)) {
        std::wstring wsPath2 = processPath;
        std::transform(wsPath2.begin(), wsPath2.end(), wsPath2.begin(), ::tolower);

        if (wsPath2.find(L"ghost-proxifier.exe") != std::wstring::npos ||
            wsPath2.find(L"ghost_launcher") != std::wstring::npos ||
            wsPath2.find(L"ghost_core") != std::wstring::npos) {
            NetLog("[Init] Skipping self-injection for PID: %d, Path: %ls", pid, processPath);
            return false;
        }
        NetLog("[Init] Attempting injection into: %ls (PID: %d)", processPath, pid);
    } else {
        NetLog("[Init] Attempting injection into unknown process (PID: %d)", pid);
    }

    // Try SetThreadContext (EntryDetour) first for x64 targets — this ensures
    // GhostInit() runs in the FIRST thread, which is required for Cygwin.
    if (hThread && !isWow64) {
        if (SetThreadContextInject(hProcess, hThread, fullDllPath, false, hEvent)) {
            NetLog("[Init] SetThreadContext (EntryDetour) succeeded for PID: %d", pid);
            return true;
        }
        NetLog("[Init] SetThreadContext failed for PID: %d, falling back to CreateRemoteThread", pid);
    }

    // Fallback: CreateRemoteThread (works for native Windows, breaks Cygwin)
    if (InjectDllW(hProcess)) {
        NetLog("[Init] CreateRemoteThread succeeded for PID: %d", pid);
        return true;
    }

    NetLog("[Init] FAILED to inject into PID: %d (Error: %lu)", pid, GetLastError());
    return false;
}

// --- Process Creation Hooks ---

BOOL WINAPI hook_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    DWORD newFlags = dwCreationFlags | CREATE_SUSPENDED;
    BOOL ret = real_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, newFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    if (ret && lpProcessInformation) {
        wchar_t eventName[64];
        swprintf_s(eventName, L"Global\\GhostCoreReady_%u", (unsigned int)lpProcessInformation->dwProcessId);
        HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, eventName);

        InjectIntoChild(lpProcessInformation->hProcess,
                        lpProcessInformation->hThread, hEvent);

        if (!(dwCreationFlags & CREATE_SUSPENDED)) {
            ResumeThread(lpProcessInformation->hThread);
            if (hEvent) {
                WaitForSingleObject(hEvent, 5000);
            }
        }
        if (hEvent) CloseHandle(hEvent);
    }
    return ret;
}

BOOL WINAPI hook_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    DWORD newFlags = dwCreationFlags | CREATE_SUSPENDED;
    BOOL ret = real_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, newFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    if (ret && lpProcessInformation) {
        wchar_t eventName[64];
        swprintf_s(eventName, L"Global\\GhostCoreReady_%u", (unsigned int)lpProcessInformation->dwProcessId);
        HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, eventName);

        InjectIntoChild(lpProcessInformation->hProcess,
                        lpProcessInformation->hThread, hEvent);

        if (!(dwCreationFlags & CREATE_SUSPENDED)) {
            ResumeThread(lpProcessInformation->hThread);
            if (hEvent) {
                WaitForSingleObject(hEvent, 5000);
            }
        }
        if (hEvent) CloseHandle(hEvent);
    }
    return ret;
}

// ============================================================================
// InstallProcessHooks: register process-creation MinHook hooks
// ============================================================================
void InstallProcessHooks() {
    if (real_CreateProcessW) MH_CreateHook((void*)real_CreateProcessW, (void*)hook_CreateProcessW, (void**)&real_CreateProcessW);
    if (real_CreateProcessA) MH_CreateHook((void*)real_CreateProcessA, (void*)hook_CreateProcessA, (void**)&real_CreateProcessA);
}
