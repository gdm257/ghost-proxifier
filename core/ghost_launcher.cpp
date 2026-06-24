#include <windows.h>
#include <string>

// Enable SeDebugPrivilege to bypass DACL deny entries on protected processes
// (AppContainer, process mitigations, etc.). No-op if not running as admin.
static void EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);
}

// Simple 32-bit injector helper
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) return 1;

    // Use wcstoul for wide strings
    DWORD pid = wcstoul(argv[1], NULL, 10);
    const wchar_t* dllPath = argv[2];

    if (pid == 0) return 7;

    // Enable SeDebugPrivilege before opening target — required for
    // processes with AppContainer isolation or process mitigations
    // (e.g. MS Edge renderer/utility processes).
    EnableDebugPrivilege();

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) return 2;

    void* loadLibraryAddr = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        CloseHandle(h);
        return 3;
    }

    // Convert wide path to ANSI for LoadLibraryA
    int pathLenA = WideCharToMultiByte(CP_ACP, 0, dllPath, -1, NULL, 0, NULL, NULL);
    if (pathLenA <= 0) {
        CloseHandle(h);
        return 3;
    }
    void* m = VirtualAllocEx(h, NULL, pathLenA, MEM_COMMIT, PAGE_READWRITE);
    if (!m) {
        CloseHandle(h);
        return 4;
    }

    std::string pathA(pathLenA, '\0');
    WideCharToMultiByte(CP_ACP, 0, dllPath, -1, &pathA[0], pathLenA, NULL, NULL);

    if (!WriteProcessMemory(h, m, pathA.c_str(), pathLenA, NULL)) {
        VirtualFreeEx(h, m, 0, MEM_RELEASE);
        CloseHandle(h);
        return 5;
    }

    HANDLE t = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, m, 0, NULL);
    if (t) {
        DWORD waitResult = WaitForSingleObject(t, 10000);
        DWORD loadResult = 0;
        bool ok = waitResult == WAIT_OBJECT_0 &&
                  GetExitCodeThread(t, &loadResult) &&
                  loadResult != 0;
        CloseHandle(t);
        VirtualFreeEx(h, m, 0, MEM_RELEASE);
        CloseHandle(h);
        return ok ? 0 : 8;
    }

    VirtualFreeEx(h, m, 0, MEM_RELEASE);
    CloseHandle(h);
    return 6;
}
