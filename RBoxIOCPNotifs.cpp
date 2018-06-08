//
// Created by hx1997 on 2018/3/11.
//

#define BUFSIZE 256

#include <cstdio>
#include <windows.h>
#include "RBoxMessage.h"

void PollCompletionPort(HANDLE hIocp) {
    DWORD dwEvent;
    ULONG_PTR lpCompKey;
    LPOVERLAPPED lpOverlapped;
    char msg[BUFSIZE];

    DWORD dwPID;
    HANDLE hProcess;
    CHAR szPath[MAX_PATH] = "???";
    DWORD dwSize = MAX_PATH;

    while(true) {
        if (!GetQueuedCompletionStatus(hIocp, &dwEvent, &lpCompKey, &lpOverlapped, 100))
            continue;

        switch (dwEvent) {
            case JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO:
                IssueMessage("All processes have ended in the sandbox!", MSGTYPE_INFO);
                break;
            case JOB_OBJECT_MSG_NEW_PROCESS:
                dwPID = (DWORD)lpOverlapped;
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, dwPID);
                QueryFullProcessImageNameA(hProcess, 0, szPath, &dwSize);
                CloseHandle(hProcess);

                sprintf(msg, "Process run: [%ld] %s", dwPID, szPath);
                IssueMessage(msg, MSGTYPE_INFO);
                break;
            case JOB_OBJECT_MSG_EXIT_PROCESS:
                dwPID = (DWORD)lpOverlapped;
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, dwPID);
                QueryFullProcessImageNameA(hProcess, 0, szPath, &dwSize);
                CloseHandle(hProcess);

                sprintf(msg, "Process exited: [%ld] %s", dwPID, szPath);
                IssueMessage(msg, MSGTYPE_INFO);
                break;
            case JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS:
                dwPID = (DWORD)lpOverlapped;
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, dwPID);
                QueryFullProcessImageNameA(hProcess, 0, szPath, &dwSize);
                CloseHandle(hProcess);

                sprintf(msg, "Process crashed: [%ld] %s", dwPID, szPath);
                IssueMessage(msg, MSGTYPE_INFO);
                break;
            case 0xCAFE:
                // A special signal that terminates the thread
                return;
            default:
                break;
        }
    }
}