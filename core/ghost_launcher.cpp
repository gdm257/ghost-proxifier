#include <windows.h>
#include <string>

// Simple 32-bit injector helper
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) return 1;

    // Use wcstoul for wide strings
    DWORD pid = wcstoul(argv[1], NULL, 10);
    const wchar_t* dllPath = argv[2];

    if (pid == 0) return 7;

    HANDLE h = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!h) return 2;

    void* loadLibraryAddr = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    if (!loadLibraryAddr) {
        CloseHandle(h);
        return 3;
    }

    size_t pathLen = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* m = VirtualAllocEx(h, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!m) {
        CloseHandle(h);
        return 4;
    }

    if (!WriteProcessMemory(h, m, (void*)dllPath, pathLen, NULL)) {
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
