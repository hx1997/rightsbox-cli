//
// Created by hx1997 on 2017/11/12.
//

#include <string>
#include <thread>
#include <userenv.h>

#pragma comment(lib, "userenv.lib")

#include "RBoxRun.h"
#include "RBoxIOCPNotifs.h"
#include "Broker.h"
#include "BrokerProtocol.h"
#include "RBoxMessage.h"

// Forward declarations
DWORD RunWithLowToken(HANDLE hToken, LPCWSTR szExePath, LPCWSTR szCmdLine, HANDLE &hProcess, HANDLE &hThread);
DWORD InjectHookDll(HANDLE hProcess, LPCWSTR szDllPath);

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

Sandbox::~Sandbox() {
    if (broker) {
        broker->Stop();
        delete broker;
    }
    if (sandboxProcess) {
        CloseHandle(sandboxProcess);
        sandboxProcess = nullptr;
    }
    delete job;
}

DWORD Sandbox::RunSandboxed(LPCWSTR szPath, BOOL bDropRights) {
    DWORD fStatus;
    HANDLE hToken, hNewToken = nullptr;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT |
                                               TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken))
        return GetLastError();

    // Initialize and start the broker
    this->broker = new Broker();
    if ((fStatus = this->broker->Initialize(hToken)) != ERROR_SUCCESS) {
        char msg[128];
        sprintf(msg, "Broker initialization failed with error %lu", fStatus);
        IssueMessage(msg, MSGTYPE_ERROR);
        delete this->broker;
        this->broker = nullptr;
        goto Cleanup;
    }

    if ((fStatus = this->broker->Start()) != ERROR_SUCCESS) {
        char msg[128];
        sprintf(msg, "Broker start failed with error %lu", fStatus);
        IssueMessage(msg, MSGTYPE_ERROR);
        delete this->broker;
        this->broker = nullptr;
        goto Cleanup;
    }

    // Set the pipe name in the environment for the child process to inherit
    SetEnvironmentVariable(BROKER_PIPE_ENV_VAR, this->broker->GetPipeName());

    if (bDropRights) {
        fStatus = RestrictToken(hToken, hNewToken, true);
        if (fStatus != ERROR_SUCCESS)
            goto Cleanup;

        if (hNewToken) {
            CloseHandle(hToken);
            hToken = hNewToken;
        }
    } else {
        if (!DuplicateTokenEx(hToken, 0, nullptr, SecurityAnonymous, TokenPrimary, &hToken)) {
            CloseHandle(hToken);
            return GetLastError();
        }
    }

    {
        HANDLE hProcess = nullptr;
        HANDLE hThread = nullptr;

        // Determine paths for RBoxRunner.exe and RBoxHook.dll (same directory as RightsBox.exe)
        WCHAR szExeDir[MAX_PATH];
        GetModuleFileName(nullptr, szExeDir, MAX_PATH);
        WCHAR *pSlash = wcsrchr(szExeDir, L'\\');
        if (pSlash)
            *(pSlash + 1) = L'\0';

        WCHAR szRunnerPath[MAX_PATH];
        wcscpy_s(szRunnerPath, szExeDir);
        wcscat_s(szRunnerPath, L"RBoxRunner.exe");

        WCHAR szDllPath[MAX_PATH];
        wcscpy_s(szDllPath, szExeDir);
#ifdef _WIN64
        wcscat_s(szDllPath, L"RBoxHook64.dll");
#else
        wcscat_s(szDllPath, L"RBoxHook32.dll");
#endif

        // Build command line: RBoxRunner.exe "target path"
        // If szPath is nullptr, RBoxRunner runs in interactive mode
        std::wstring runnerCmdLine;
        AppendQuotedArg(runnerCmdLine, szRunnerPath);
        if (szPath) {
            AppendQuotedArg(runnerCmdLine, szPath);
        }

        if ((fStatus = RunWithLowToken(hToken, szRunnerPath, runnerCmdLine.c_str(), hProcess, hThread)) != ERROR_SUCCESS) {
            goto Cleanup;
        }

        // Inject the hook DLL into RBoxRunner while it's still suspended
        {

            DWORD dwInjectStatus = InjectHookDll(hProcess, szDllPath);
            if (dwInjectStatus != ERROR_SUCCESS) {
                char msg[128];
                sprintf(msg, "Hook DLL injection failed with error %lu", dwInjectStatus);
                IssueMessage(msg, MSGTYPE_WARNING);
                // Continue anyway — sandbox still works, just without broker
            } else {
                IssueMessage("Hook DLL injected successfully", MSGTYPE_INFO);
            }
        }

        // Clear the env var from the parent process (child already inherited it)
        SetEnvironmentVariable(BROKER_PIPE_ENV_VAR, nullptr);

        if ((fStatus = this->job->ConfineProcessToJob(hProcess)) != ERROR_SUCCESS) {
            TerminateProcess(hProcess, ERROR_SUCCESS);
            goto Cleanup;
        }

        if ((fStatus = this->job->RegisterJobNotify()) != ERROR_SUCCESS) {
            TerminateProcess(hProcess, ERROR_SUCCESS);
            goto Cleanup;
        }

        ResumeThread(hThread);

        this->sandboxProcess = hProcess;
        hProcess = nullptr;

        if (hProcess)
            CloseHandle(hProcess);
        if (hThread)
            CloseHandle(hThread);
    }

    Cleanup:
    if (hToken)
        CloseHandle(hToken);
    if (hNewToken && hToken != hNewToken)
        CloseHandle(hNewToken);

    // Clean up env var on error path too
    SetEnvironmentVariable(BROKER_PIPE_ENV_VAR, nullptr);

    if (fStatus != ERROR_SUCCESS && this->broker) {
        this->broker->Stop();
        delete this->broker;
        this->broker = nullptr;
    }

    return fStatus;
}

DWORD Sandbox::WaitForSandbox(DWORD &dwExitCode) {
    dwExitCode = 0;

    if (!this->sandboxProcess)
        return ERROR_INVALID_HANDLE;

    DWORD waitResult = WaitForSingleObject(this->sandboxProcess, INFINITE);
    if (waitResult != WAIT_OBJECT_0)
        return GetLastError();

    if (!GetExitCodeProcess(this->sandboxProcess, &dwExitCode))
        return GetLastError();

    CloseHandle(this->sandboxProcess);
    this->sandboxProcess = nullptr;

    return ERROR_SUCCESS;
}

DWORD RunWithLowToken(HANDLE hToken, LPCWSTR szExePath, LPCWSTR szCmdLine, HANDLE &hProcess, HANDLE &hThread) {
    DWORD fStatus = 0;
    LPVOID pEnvironment = nullptr;

    if ((fStatus = SetTokenLowIL(hToken)) != ERROR_SUCCESS)
        return fStatus;

    STARTUPINFO si = {};
    PROCESS_INFORMATION pi = {};

    si.cb = sizeof(si);

    // CreateProcessAsUser needs a mutable command line buffer
    WCHAR szCmdBuf[MAX_PATH * 2] = {};
    if (szCmdLine)
        wcsncpy_s(szCmdBuf, szCmdLine, _TRUNCATE);

    if (!CreateEnvironmentBlock(&pEnvironment, hToken, TRUE))
        return GetLastError();

    if (!CreateProcessAsUser(hToken, szExePath, szCmdBuf[0] ? szCmdBuf : nullptr,
                             nullptr, nullptr, false,
                             CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                             pEnvironment, nullptr, &si, &pi)) {
        fStatus = GetLastError();
        DestroyEnvironmentBlock(pEnvironment);
        return fStatus;
    }

    DestroyEnvironmentBlock(pEnvironment);

    hProcess = pi.hProcess;
    hThread = pi.hThread;

    return fStatus;
}

DWORD Sandbox::StopSandbox() {
    if (this->sandboxProcess) {
        CloseHandle(this->sandboxProcess);
        this->sandboxProcess = nullptr;
    }

    // Stop the broker first (graceful client disconnect)
    if (this->broker) {
        this->broker->Stop();
        delete this->broker;
        this->broker = nullptr;
    }

    this->job->StopJob();

    return ERROR_SUCCESS;
}

DWORD Sandbox::Job::StopJob() {
    TerminateJobObject(this->hJob, ERROR_SUCCESS);
    CloseHandle(this->hJob);
    this->hJob = nullptr;

    return ERROR_SUCCESS;
}

DWORD Sandbox::Job::ConfineProcessToJob(HANDLE hProcess) {
    if (!hProcess)
        return ERROR_INVALID_HANDLE;

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);

    if (!this->hJob)
        if (!(this->hJob = CreateJobObject(&sa, nullptr)))
            return GetLastError();

    if (!AssignProcessToJobObject(this->hJob, hProcess)) {
        CloseHandle(this->hJob);
        return GetLastError();
    }

    if (!SetJobLimits(JOB_OBJECT_UILIMIT_EXITWINDOWS)) {
        CloseHandle(this->hJob);
        return GetLastError();
    }

    return ERROR_SUCCESS;
}

int Sandbox::Job::SetJobLimits(DWORD dwUILimits) {
    JOBOBJECT_BASIC_UI_RESTRICTIONS jbui = {};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};

    jbui.UIRestrictionsClass = dwUILimits;
    if (!SetInformationJobObject(this->hJob, JobObjectBasicUIRestrictions, &jbui, sizeof(jbui)))
        return 0;

    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(this->hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli)))
        return 0;

    return 1;
}

DWORD Sandbox::Job::RegisterJobNotify() {
    if (!(this->hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, NULL, NULL))) {
        CloseHandle(this->hJob);
        return GetLastError();
    }

    JOBOBJECT_ASSOCIATE_COMPLETION_PORT joacp = {this->hJob, this->hIocp};

    if (!SetInformationJobObject(this->hJob, JobObjectAssociateCompletionPortInformation, &joacp, sizeof(joacp)))
        return GetLastError();

    std::thread t1(PollCompletionPort, this->hIocp);
    t1.detach();

    return ERROR_SUCCESS;
}

DWORD InjectHookDll(HANDLE hProcess, LPCWSTR szDllPath) {
    SIZE_T dwSize = (lstrlenW(szDllPath) + 1) * sizeof(WCHAR);
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, nullptr, dwSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf)
        return GetLastError();

    if (!WriteProcessMemory(hProcess, pRemoteBuf, szDllPath, dwSize, nullptr)) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return err;
    }

    auto pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibrary) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return ERROR_PROC_NOT_FOUND;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibrary, pRemoteBuf, 0, nullptr);
    if (!hThread) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return err;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    return ERROR_SUCCESS;
}