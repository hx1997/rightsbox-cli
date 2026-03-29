//
// Created by hx1997 on 2018/3/7.
//

#include <cstdio>
#include <windows.h>

#include "RBoxInit.h"
#include "RBoxMessage.h"
#include "RBoxRun.h"

// Forward declarations
int DisplayMenu();
int RoutineRun();
int RoutineStop();
int RoutineOptions();
int RoutineExit();

Sandbox *box;

int DispatchRunSandboxed(LPCWSTR szTargetPath) {
    // Initialize sandbox runtime
    if (!(box = InitRightsBox()))
        return -1;

    DWORD fStatus = box->RunSandboxed(szTargetPath, true);
    DWORD exitCode = 0;
    if (fStatus != ERROR_SUCCESS) {
        char msg[128];
        sprintf(msg, "RunSandboxed failed with error %lu", fStatus);
        IssueMessage(msg, MSGTYPE_ERROR);
    } else {
        fStatus = box->WaitForSandbox(exitCode);
        if (fStatus != ERROR_SUCCESS) {
            char msg[128];
            sprintf(msg, "WaitForSandbox failed with error %lu", fStatus);
            IssueMessage(msg, MSGTYPE_ERROR);
        }
    }

    delete box;
    box = nullptr;

    if (fStatus != ERROR_SUCCESS) {
        return 1;
    }

    return (int)exitCode;
}

int DispatchRoutineEntry() {
    // Display banner
    printf("\t\t=========================\r\n");
    printf("\t\tRightsBox Control\r\n");
    printf("\t\tReleased by hx1997 under the MIT License, 2018\r\n");
    printf("\t\t=========================\r\n");
    printf("\r\n");

    // Initialize
    if (!(box = InitRightsBox()))
        return -1;

    // Display menu
    BOOL bDontDisplayMenu = FALSE;

    while (!bDontDisplayMenu) {
        bDontDisplayMenu = DisplayMenu();
    }

    // Destroy Sandbox object
    delete box;

    return 0;
}

int DisplayMenu() {
    // Menu
    printf("\r\nMenu:\r\n");
    printf("1.\tRun a program sandboxed\r\n");
    printf("2.\tRun as...\r\n");
    printf("3.\tStop sandbox\r\n");
    printf("4.\tOptions\r\n");
    printf("5.\tExit\r\n");
    printf("Choose the action you want: ");

    // Wait for input
    WCHAR szChoice[5] = {};
    _getws_s(szChoice, 5);

    // Do action
    if (lstrcmpW(szChoice, L"1") == 0) {
        RoutineRun();
    } else if (lstrcmpW(szChoice, L"2") == 0) {
        //DisplayRunAsMenu();
    } else if (lstrcmpW(szChoice, L"3") == 0) {
        RoutineStop();
    } else if (lstrcmpW(szChoice, L"4") == 0) {
        RoutineOptions();
    } else if (lstrcmpW(szChoice, L"5") == 0) {
        RoutineExit();
        return -1;
    } else {
        IssueMessage("Invalid command!", MSGTYPE_ERROR);
    }

    return 0;
}

int RoutineRun() {
    printf("Enter the path of the program to sandbox (or press Enter for interactive mode): ");
    WCHAR szPath[MAX_PATH] = {};
    _getws_s(szPath, MAX_PATH);

    // Trim leading spaces
    WCHAR *p = szPath;
    while (*p == L' ' || *p == L'\t') p++;

    // If empty, pass nullptr for interactive RBoxRunner mode
    LPCWSTR szTarget = (p[0] != L'\0') ? p : nullptr;

    DWORD fStatus = box->RunSandboxed(szTarget, true);
    if (fStatus != ERROR_SUCCESS) {
        char msg[128];
        sprintf(msg, "RunSandboxed failed with error %lu", fStatus);
        IssueMessage(msg, MSGTYPE_ERROR);
    }
    return (fStatus != ERROR_SUCCESS);
}

int RoutineStop() {
    box->StopSandbox();
    return 0;
}

int RoutineOptions() {
    //return ConfigSandbox();
    return 0;
}

int RoutineExit() {
    //int ret = StopSandbox();
    return 0;
}