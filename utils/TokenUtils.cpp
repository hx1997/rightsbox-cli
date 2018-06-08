//
// Created by hx1997 on 2017/11/12.
//

#include "TokenUtils.h"

BOOL IsAdmin() {
    PSID pAdminSid;
    BOOL bIsAdmin;

    if (!ConvertStringSidToSid(ADMIN_STRING_SID, &pAdminSid))
        return 0;

    if (!CheckTokenMembership(nullptr, pAdminSid, &bIsAdmin))
        return 0;

    LocalFree(pAdminSid);

    return bIsAdmin;
}

DWORD SetTokenLowIL(HANDLE hToken) {
    PSID pIntegritySid;

    if (!ConvertStringSidToSid(LOW_IL_STRING_SID, &pIntegritySid))
        return GetLastError();

    TOKEN_MANDATORY_LABEL til = {};

    til.Label.Attributes = SE_GROUP_INTEGRITY;
    til.Label.Sid = pIntegritySid;

    if (!SetTokenInformation(hToken, TokenIntegrityLevel, &til, sizeof(til)))
        return GetLastError();

    LocalFree(pIntegritySid);

    return ERROR_SUCCESS;
}

DWORD GetTokenInfo(HANDLE hToken, void* &InfoBuff) {
    DWORD dwSize;

    // Retrieve the size of buffer needed
    if (!GetTokenInformation(hToken, TokenGroups, nullptr, 0, &dwSize)) {
        DWORD dwResult = GetLastError();
        if (dwResult != ERROR_INSUFFICIENT_BUFFER)
            return dwResult;
    }

    InfoBuff = malloc(dwSize);

    if (!InfoBuff)
        return ERROR_NOT_ENOUGH_MEMORY;

    if (!GetTokenInformation(hToken, TokenGroups, InfoBuff, dwSize, &dwSize))
        return GetLastError();

    return ERROR_SUCCESS;
}

// TODO: Split into smaller functions
DWORD RestrictToken(HANDLE hToken, HANDLE &hNewToken, BOOL bWriteProtected) {
    DWORD fStatus;
    PTOKEN_GROUPS pTokenGrps;

    if ((fStatus = GetTokenInfo(hToken, (void*&)pTokenGrps)) != ERROR_SUCCESS)
        return fStatus;

    DWORD nGroupCount = pTokenGrps->GroupCount - 1;
    auto *SidsToDelete = new SID_AND_ATTRIBUTES[nGroupCount];
    DWORD dwSids = 0;
    LPWSTR StringSid;

    PSID pLogonIdSid = nullptr;

    // Label deny-only for all groups except Logon ID, Everyone, Users, and INTERACTIVE
    for (unsigned int i = 0; i < pTokenGrps->GroupCount; i++) {
        if (IsValidSid(pTokenGrps->Groups[i].Sid)) {
            if (ConvertSidToStringSid(pTokenGrps->Groups[i].Sid, &StringSid)) {
                // Is this SID the Logon ID?
                if (SE_GROUP_LOGON_ID == (pTokenGrps->Groups[i].Attributes & SE_GROUP_LOGON_ID)) {
                    pLogonIdSid = pTokenGrps->Groups[i].Sid;
                } else if ((lstrcmp(StringSid, EVERYONE_STRING_SID) != 0)
                           && (lstrcmp(StringSid, USERS_STRING_SID) != 0)
                           && (lstrcmp(StringSid, INTERACTIVE_STRING_SID) != 0)) {
                    SidsToDelete[dwSids].Sid = pTokenGrps->Groups[i].Sid;
                    dwSids++;
                }
            }
        }
    }

    PSID pAdminSid, pSystemSid, pRestrictedSid, pUsersSid, pEveryoneSid;

    ConvertStringSidToSid(ADMIN_STRING_SID, &pAdminSid);
    ConvertStringSidToSid(SYSTEM_STRING_SID, &pSystemSid);
    ConvertStringSidToSid(RESTRICTED_STRING_SID, &pRestrictedSid);
    ConvertStringSidToSid(USERS_STRING_SID, &pUsersSid);
    ConvertStringSidToSid(EVERYONE_STRING_SID, &pEveryoneSid);

    SID_AND_ATTRIBUTES SidsToRestrict[4] = {};

    // Restrict Everyone, Users, RESTRICTED, and Logon ID
    SidsToRestrict[0].Sid = pEveryoneSid;
    SidsToRestrict[1].Sid = pUsersSid;
    SidsToRestrict[2].Sid = pRestrictedSid;
    SidsToRestrict[3].Sid = pLogonIdSid;

    DWORD dwFlags;

    if (IsWindowsVistaOrGreater())
        dwFlags = (bWriteProtected ?
                   (DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED) :
                   (DISABLE_MAX_PRIVILEGE | LUA_TOKEN));
    else
        dwFlags = (bWriteProtected ?
                   (DISABLE_MAX_PRIVILEGE | LUA_TOKEN) :
                   (DISABLE_MAX_PRIVILEGE));

    if (!CreateRestrictedToken(hToken, dwFlags, dwSids, SidsToDelete, 0, nullptr, 4, SidsToRestrict, &hNewToken))
        return GetLastError();

    DWORD dwAcl;
    char buf[0x400];
    auto pAcl = (PACL)buf;

    TOKEN_DEFAULT_DACL TokenDacl = {};
    TokenDacl.DefaultDacl = pAcl;

    // Calculate ACL length
    dwAcl = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3 + (GetLengthSid(pLogonIdSid) - 4) +
            (GetLengthSid(pAdminSid) - 4) + (GetLengthSid(pSystemSid) - 4) + 3;
    dwAcl &= 0xFFFFFFFC;

    if (!InitializeAcl(pAcl, dwAcl, ACL_REVISION)) {
        fStatus = GetLastError();
        goto Cleanup;
    }

    // Allow full control for System, Administrators, and Logon ID
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, pSystemSid)) {
        fStatus = GetLastError();
        goto Cleanup;
    }

    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, pAdminSid)) {
        fStatus = GetLastError();
        goto Cleanup;
    }

    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, pLogonIdSid)) {
        fStatus = GetLastError();
        goto Cleanup;
    }

    if (!SetTokenInformation(hNewToken, TokenDefaultDacl, &TokenDacl, sizeof(TOKEN_DEFAULT_DACL))) {
        fStatus = GetLastError();
        goto Cleanup;
    }

    Cleanup:
    if (fStatus != ERROR_SUCCESS) CloseHandle(hNewToken);
    delete SidsToDelete;

    LocalFree(pAdminSid);
    LocalFree(pSystemSid);
    LocalFree(pRestrictedSid);
    LocalFree(pUsersSid);
    LocalFree(pEveryoneSid);
    LocalFree(pLogonIdSid);

    return fStatus;
}