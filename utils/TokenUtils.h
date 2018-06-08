//
// Created by hx1997 on 2017/11/12.
//

#ifndef RIGHTSBOX_CPP_TOKENUTILS_H
#define RIGHTSBOX_CPP_TOKENUTILS_H

#include <windows.h>
#include "./OSVersionUtils.h"
#include <Sddl.h>

#define ADMIN_STRING_SID L"S-1-5-32-544"
#define LOW_IL_STRING_SID L"S-1-16-4096"
#define EVERYONE_STRING_SID L"S-1-1-0"
#define USERS_STRING_SID L"S-1-5-32-545"
#define INTERACTIVE_STRING_SID L"S-1-5-4"
#define SYSTEM_STRING_SID L"S-1-5-18"
#define RESTRICTED_STRING_SID L"S-1-5-12"

BOOL IsAdmin();
DWORD SetTokenLowIL(HANDLE hToken);
DWORD RestrictToken(HANDLE hToken, HANDLE &hNewToken, BOOL bWriteProtected);

#endif //RIGHTSBOX_CPP_TOKENUTILS_H