//
// Created by hx1997 on 2017/11/12.
//

#include <thread>

#include "RBoxRun.h"
#include "RBoxIOCPNotifs.h"

// Forward declarations
DWORD RunWithLowToken(HANDLE hToken, LPCWSTR szPath, HANDLE &hProcess, HANDLE &hThread);

DWORD Sandbox::RunSandboxed(LPCWSTR szPath, BOOL bDropRights) {
    DWORD fStatus;
    HANDLE hToken, hNewToken = nullptr;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT |
                                               TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken))
        return GetLastError();

    if (bDropRights) {
        // No need to duplicate the token since we are creating a NEW one based on the original
        RestrictToken(hToken, hNewToken, true);

        if (hNewToken)
            hToken = hNewToken;
    } else {
        if (!DuplicateTokenEx(hToken, 0, nullptr, SecurityAnonymous, TokenPrimary, &hToken)) {
            CloseHandle(hToken);
            return GetLastError();
        }
    }

    HANDLE hProcess;
    HANDLE hThread;

    if ((fStatus = RunWithLowToken(hToken, szPath, hProcess, hThread)) != ERROR_SUCCESS) {
        goto Cleanup;
    }

    if ((fStatus = this->job->ConfineProcessToJob(hProcess)) != ERROR_SUCCESS) {
        TerminateProcess(hProcess, ERROR_SUCCESS);
        goto Cleanup;
    }

    if ((fStatus = this->job->RegisterJobNotify()) != ERROR_SUCCESS) {
        TerminateProcess(hProcess, ERROR_SUCCESS);
        goto Cleanup;
    }

    ResumeThread(hThread);

    Cleanup:
    CloseHandle(hProcess);
    CloseHandle(hThread);
    CloseHandle(hToken);
    CloseHandle(hNewToken);

    return fStatus;
}

DWORD RunWithLowToken(HANDLE hToken, LPCWSTR szPath, HANDLE &hProcess, HANDLE &hThread) {
    DWORD fStatus = 0;

    if ((fStatus = SetTokenLowIL(hToken)) != ERROR_SUCCESS)
        return fStatus;

    STARTUPINFO si = {};
    PROCESS_INFORMATION pi = {};

    si.cb = sizeof(si);

    if (!CreateProcessAsUser(hToken, szPath, nullptr, nullptr, nullptr, false,
                             CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
        return GetLastError();

    hProcess = pi.hProcess;
    hThread = pi.hThread;

    return fStatus;
}

DWORD Sandbox::StopSandbox() {
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