#include <windows.h>
#include <vector>
#include <tlhelp32.h>

std::vector<DWORD> GetProcessTree(DWORD parentPid) {
    std::vector<DWORD> children;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return children;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ParentProcessID == parentPid) {
                children.push_back(pe.th32ProcessID);
                // Recursively get grandchildren
                auto grandchildren = GetProcessTree(pe.th32ProcessID);
                children.insert(children.end(), grandchildren.begin(), grandchildren.end());
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return children;
}
