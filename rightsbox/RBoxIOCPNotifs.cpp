//
// Created by hx1997 on 2018/3/11.
//

#define BUFSIZE 512
#define MAX_TRACKED_PROCESSES 256

#include <cstdio>
#include <cstring>
#include <windows.h>
#include "RBoxMessage.h"

struct ProcessEntry {
    DWORD dwPID;
    CHAR  szPath[MAX_PATH];
};

static ProcessEntry g_processCache[MAX_TRACKED_PROCESSES];
static DWORD g_processCacheCount = 0;

static void CacheProcessPath(DWORD dwPID, const CHAR* szPath) {
    if (g_processCacheCount < MAX_TRACKED_PROCESSES) {
        g_processCache[g_processCacheCount].dwPID = dwPID;
        lstrcpyA(g_processCache[g_processCacheCount].szPath, szPath);
        g_processCacheCount++;
    }
}

static const CHAR* LookupProcessPath(DWORD dwPID) {
    for (DWORD i = 0; i < g_processCacheCount; i++) {
        if (g_processCache[i].dwPID == dwPID)
            return g_processCache[i].szPath;
    }
    return nullptr;
}

static DWORD QueryProcessPath(DWORD dwPID, CHAR* szOut, DWORD cchOut) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
    if (!hProcess)
        return 0;

    DWORD dwSize = cchOut;
    BOOL ok = QueryFullProcessImageNameA(hProcess, 0, szOut, &dwSize);
    CloseHandle(hProcess);
    return ok ? dwSize : 0;
}

void PollCompletionPort(HANDLE hIocp) {
    DWORD dwEvent;
    ULONG_PTR lpCompKey;
    LPOVERLAPPED lpOverlapped;
    char msg[BUFSIZE];

    DWORD dwPID;
    CHAR szPath[MAX_PATH];
    const CHAR* cached;

    while(true) {
        if (!GetQueuedCompletionStatus(hIocp, &dwEvent, &lpCompKey, &lpOverlapped, 100))
            continue;

        switch (dwEvent) {
            case JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO:
                IssueMessage("All processes have ended in the sandbox!", MSGTYPE_INFO);
                break;
            case JOB_OBJECT_MSG_NEW_PROCESS:
                dwPID = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(lpOverlapped));
                lstrcpyA(szPath, "???");
                if (QueryProcessPath(dwPID, szPath, MAX_PATH))
                    CacheProcessPath(dwPID, szPath);

                sprintf(msg, "Process run: [%ld] %s", dwPID, szPath);
                IssueMessage(msg, MSGTYPE_INFO);
                break;
            case JOB_OBJECT_MSG_EXIT_PROCESS:
                dwPID = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(lpOverlapped));
                cached = LookupProcessPath(dwPID);
                lstrcpyA(szPath, cached ? cached : "???");

                sprintf(msg, "Process exited: [%ld] %s", dwPID, szPath);
                IssueMessage(msg, MSGTYPE_INFO);
                break;
            case JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS:
                dwPID = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(lpOverlapped));
                cached = LookupProcessPath(dwPID);
                lstrcpyA(szPath, cached ? cached : "???");

                sprintf(msg, "Process crashed: [%ld] %s", dwPID, szPath);
                IssueMessage(msg, MSGTYPE_INFO);
                break;
            case 0xCAFE:
                return;
            default:
                break;
        }
    }
}