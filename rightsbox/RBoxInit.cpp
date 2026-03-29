//
// Created by hx1997 on 2018/3/8.
//

#include <windows.h>
#include "utils/OSVersionUtils.h"
#include "utils/TokenUtils.h"
#include "RBoxMessage.h"
#include "RBoxRun.h"

int CheckOS();
int RestartElevated();

Sandbox *InitRightsBox() {
    // Check Windows version since we rely heavily on Vista+ security features
    if (CheckOS() != ERROR_SUCCESS)
        return nullptr;

    // Make sure we run with administrative rights to prevent UAC elevation of sandboxed processes
    if (!IsAdmin()) {
        IssueMessage("Administrative rights required. Press any key to restart elevated.", MSGTYPE_INFO);
        system("pause");
        RestartElevated();
        return nullptr;
    }

    return new Sandbox();
}

int CheckOS() {
    if (!IsWindowsVistaOrGreater()) {
        IssueMessage("Unsupported OS! Exiting...", MSGTYPE_ERROR);
        return ERROR_NOT_SUPPORTED;
    }

    return ERROR_SUCCESS;
}

int RestartElevated() {
    WCHAR szModulePath[MAX_PATH];

    // Get path to the RightsBox executable itself
    if (!GetModuleFileName(nullptr, szModulePath, MAX_PATH))
        return -1;

    if ((int)ShellExecute(nullptr, L"runas", szModulePath, nullptr, nullptr, SW_SHOWNORMAL) <= 32)
        return -1;

    return 0;
}