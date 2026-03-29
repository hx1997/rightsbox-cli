//
// RBoxRunner.cpp — Sandboxed launcher. Runs inside the sandbox (same bitwidth
// as RightsBox.exe) so RBoxHook.dll injection always works. Accepts a program
// path as argv[1], or prompts interactively. The NtCreateUserProcess hook in
// RBoxHook.dll propagates the hook DLL into any child process we create.
//

#include <cstdio>
#include <windows.h>

static DWORD LaunchProgram(LPCWSTR szPath, DWORD &dwExitCode) {
    STARTUPINFO si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    dwExitCode = 0;

    // Use CREATE_NEW_CONSOLE so the child gets its own console window.
    // We pass szPath as both the application and command line — if the
    // program needs arguments, the user can include them in the string.
    WCHAR szCmdLine[MAX_PATH + 1];
    wcsncpy_s(szCmdLine, szPath, _TRUNCATE);

    if (!CreateProcess(nullptr, szCmdLine, nullptr, nullptr, FALSE,
                       CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        return GetLastError();
    }

    // Wait for the child to exit, then return its exit code.
    WaitForSingleObject(pi.hProcess, INFINITE);

    GetExitCodeProcess(pi.hProcess, &dwExitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t *argv[]) {
    if (argc >= 2) {
        // Program path provided via CLI argument
        DWORD childExitCode = 0;
        DWORD err = LaunchProgram(argv[1], childExitCode);
        if (err != ERROR_SUCCESS) {
            fprintf(stderr, "[RBoxRunner] CreateProcess failed with error %lu\n", err);
            return 1;
        }
        return (int)childExitCode;
    }

    // Interactive mode — prompt for program path in a loop
    printf("RightsBox Sandboxed Runner\n");
    printf("Type a program path to run (or 'exit' to quit).\n\n");

    WCHAR szInput[MAX_PATH] = {};
    while (true) {
        printf("RBoxRunner> ");
        if (!_getws_s(szInput, MAX_PATH))
            break;

        // Trim leading/trailing spaces
        WCHAR *p = szInput;
        while (*p == L' ' || *p == L'\t') p++;
        if (*p == L'\0') continue;

        // Check for exit command
        if (_wcsicmp(p, L"exit") == 0 || _wcsicmp(p, L"quit") == 0)
            break;

        DWORD childExitCode = 0;
        DWORD err = LaunchProgram(p, childExitCode);
        if (err != ERROR_SUCCESS) {
            fprintf(stderr, "[RBoxRunner] CreateProcess failed with error %lu\n", err);
        } else {
            printf("[RBoxRunner] Program exited with code %lu.\n", childExitCode);
        }
    }

    return 0;
}
