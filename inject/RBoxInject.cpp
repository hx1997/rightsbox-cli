//
// RBoxInject.cpp — Cross-architecture DLL injection helper.
//
// Usage: RBoxInject<32|64>.exe <inherited_process_handle> "<DLL path>"
//
// Launched by RBoxHook.dll when a hooked process spawns a child of a
// different architecture. This helper is built as the SAME bitwidth as
// the target, so the standard CreateRemoteThread + LoadLibraryW technique
// works — kernel32.dll base and LoadLibraryW address are correct.
//
// The target process handle is inherited (bInheritHandles=TRUE) from the
// parent, so no OpenProcess call is needed.
//

#include <windows.h>
#include <cstdlib>

int wmain(int argc, wchar_t *argv[]) {
    if (argc < 3)
        return (int)ERROR_BAD_ARGUMENTS;

    // argv[1] = numeric value of the inherited process handle
    // argv[2] = full path to the hook DLL to inject
    HANDLE hProcess = (HANDLE)(ULONG_PTR)_wcstoui64(argv[1], nullptr, 10);
    LPCWSTR szDllPath = argv[2];

    SIZE_T dwSize = (lstrlenW(szDllPath) + 1) * sizeof(WCHAR);
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, nullptr, dwSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf)
        return (int)GetLastError();

    if (!WriteProcessMemory(hProcess, pRemoteBuf, szDllPath, dwSize, nullptr)) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return (int)err;
    }

    auto pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibrary) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return (int)ERROR_PROC_NOT_FOUND;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibrary, pRemoteBuf, 0, nullptr);
    if (!hThread) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return (int)err;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

    return 0;
}
