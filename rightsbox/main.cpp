#include <cstdio>
#include <string>
#include <windows.h>

#include "Dispatcher.h"

static void AppendQuotedArg(std::wstring &cmd, LPCWSTR arg) {
    if (!arg) {
        return;
    }

    if (!cmd.empty()) {
        cmd += L" ";
    }

    bool needsQuotes = false;
    for (const WCHAR *p = arg; *p != L'\0'; ++p) {
        if (*p == L' ' || *p == L'\t' || *p == L'\"') {
            needsQuotes = true;
            break;
        }
    }

    if (!needsQuotes) {
        cmd += arg;
        return;
    }

    cmd += L'\"';
    unsigned int backslashes = 0;
    for (const WCHAR *p = arg; *p != L'\0'; ++p) {
        if (*p == L'\\') {
            backslashes++;
            continue;
        }

        if (*p == L'\"') {
            cmd.append(backslashes * 2 + 1, L'\\');
            cmd += L'\"';
            backslashes = 0;
            continue;
        }

        if (backslashes > 0) {
            cmd.append(backslashes, L'\\');
            backslashes = 0;
        }

        cmd += *p;
    }

    if (backslashes > 0) {
        cmd.append(backslashes * 2, L'\\');
    }

    cmd += L'\"';
}

static std::wstring BuildTargetCommandLine(int argc, wchar_t *argv[]) {
    std::wstring cmd;
    for (int i = 2; i < argc; ++i) {
        AppendQuotedArg(cmd, argv[i]);
    }
    return cmd;
}

int wmain(int argc, wchar_t *argv[]) {
    SetConsoleTitle(L"RightsBox");

    if (argc >= 2 && _wcsicmp(argv[1], L"run_sandboxed") == 0) {
        if (argc < 3 || argv[2] == nullptr || argv[2][0] == L'\0') {
            fwprintf(stderr, L"Usage: RightsBox.exe run_sandboxed <program_path> [program_args ...]\n");
            return 2;
        }

        std::wstring targetCmd = BuildTargetCommandLine(argc, argv);
        return DispatchRunSandboxed(targetCmd.c_str());
    }

    DispatchRoutineEntry();
    return 0;
}