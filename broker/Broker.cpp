//
// Broker.cpp — Named pipe broker server implementation.
//

#include <cstdio>
#include <thread>
#include "Broker.h"
#include "RBoxMessage.h"
#include "utils/TokenUtils.h"

static void LogBrokerFailure(const char *operation, const char *stage, LPCWSTR target, DWORD status) {
    char msg[512];
    sprintf_s(msg, "Broker: %s %s target=%ls status=%lu", operation, stage,
              target ? target : L"<null>", status);
    IssueMessage(msg, status == ERROR_ACCESS_DENIED ? MSGTYPE_WARNING : MSGTYPE_ERROR);
}

// ============================================================================
// Construction / Destruction
// ============================================================================

Broker::Broker()
    : m_hBrokerToken(nullptr)
    , m_pSD(nullptr)
    , m_pDacl(nullptr)
    , m_pSacl(nullptr)
    , m_pLogonIdSid(nullptr)
    , m_hShutdownEvent(nullptr)
{
    ZeroMemory(m_szPipeName, sizeof(m_szPipeName));
    ZeroMemory(&m_sa, sizeof(m_sa));
}

Broker::~Broker() {
    Stop();
}

// ============================================================================
// Public API
// ============================================================================

DWORD Broker::Initialize(HANDLE hAdminToken) {
    DWORD fStatus;

    m_hShutdownEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!m_hShutdownEvent)
        return GetLastError();

    if ((fStatus = ExtractLogonIdSid(hAdminToken)) != ERROR_SUCCESS)
        return fStatus;

    if ((fStatus = CreateBrokerToken(hAdminToken)) != ERROR_SUCCESS)
        return fStatus;

    if ((fStatus = GeneratePipeName()) != ERROR_SUCCESS)
        return fStatus;

    if ((fStatus = BuildPipeSecurity()) != ERROR_SUCCESS)
        return fStatus;

    // Try to load policy from file next to the executable
    WCHAR szExePath[MAX_PATH];
    GetModuleFileName(nullptr, szExePath, MAX_PATH);
    // Replace the exe filename with policy.conf
    WCHAR *pSlash = wcsrchr(szExePath, L'\\');
    if (pSlash) {
        wcscpy_s(pSlash + 1, MAX_PATH - (pSlash + 1 - szExePath), L"policy.conf");
        if (m_policy.LoadFromFile(szExePath) != ERROR_SUCCESS) {
            IssueMessage("Broker: No policy.conf found, using defaults", MSGTYPE_INFO);
            m_policy.LoadDefaults();
        } else {
            IssueMessage("Broker: Loaded policy from policy.conf", MSGTYPE_INFO);
        }
    } else {
        m_policy.LoadDefaults();
    }

    char msg[256];
    sprintf(msg, "Broker: Initialized, pipe name: %ls", m_szPipeName);
    IssueMessage(msg, MSGTYPE_INFO);

    return ERROR_SUCCESS;
}

DWORD Broker::Start() {
    std::thread listener(ListenerThreadProc, this);
    listener.detach();

    IssueMessage("Broker: Listener started", MSGTYPE_INFO);
    return ERROR_SUCCESS;
}

DWORD Broker::Stop() {
    if (m_hShutdownEvent) {
        SetEvent(m_hShutdownEvent);
        // Give threads time to notice and clean up
        Sleep(500);
    }

    if (m_hBrokerToken)   { CloseHandle(m_hBrokerToken); m_hBrokerToken = nullptr; }
    if (m_pSD)            { LocalFree(m_pSD);   m_pSD = nullptr; }
    if (m_pDacl)          { LocalFree(m_pDacl); m_pDacl = nullptr; }
    if (m_pSacl)          { LocalFree(m_pSacl); m_pSacl = nullptr; }
    if (m_pLogonIdSid)    { LocalFree(m_pLogonIdSid); m_pLogonIdSid = nullptr; }
    if (m_hShutdownEvent) { CloseHandle(m_hShutdownEvent); m_hShutdownEvent = nullptr; }

    return ERROR_SUCCESS;
}

LPCWSTR Broker::GetPipeName() const {
    return m_szPipeName;
}

BrokerPolicy& Broker::GetPolicy() {
    return m_policy;
}

// ============================================================================
// Token Creation
// ============================================================================

DWORD Broker::CreateBrokerToken(HANDLE hAdminToken) {
    HANDLE hDupToken = nullptr;

    if (!DuplicateTokenEx(hAdminToken, TOKEN_ALL_ACCESS, nullptr,
                          SecurityImpersonation, TokenPrimary, &hDupToken))
        return GetLastError();

    // LUA_TOKEN produces the UAC-filtered standard-user token:
    // admin groups become deny-only, dangerous privileges removed.
    if (!CreateRestrictedToken(hDupToken, LUA_TOKEN,
                               0, nullptr, 0, nullptr, 0, nullptr,
                               &m_hBrokerToken)) {
        DWORD err = GetLastError();
        CloseHandle(hDupToken);
        return err;
    }

    CloseHandle(hDupToken);

    // Set to Medium IL — the "normal" user integrity level
    DWORD fStatus = SetTokenMediumIL(m_hBrokerToken);
    if (fStatus != ERROR_SUCCESS) {
        CloseHandle(m_hBrokerToken);
        m_hBrokerToken = nullptr;
    }

    return fStatus;
}

// ============================================================================
// LogonID SID Extraction
// ============================================================================

DWORD Broker::ExtractLogonIdSid(HANDLE hToken) {
    DWORD dwSize = 0;

    // Get required buffer size
    GetTokenInformation(hToken, TokenGroups, nullptr, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return GetLastError();

    auto pGroups = (PTOKEN_GROUPS)malloc(dwSize);
    if (!pGroups)
        return ERROR_NOT_ENOUGH_MEMORY;

    if (!GetTokenInformation(hToken, TokenGroups, pGroups, dwSize, &dwSize)) {
        DWORD err = GetLastError();
        free(pGroups);
        return err;
    }

    DWORD fStatus = ERROR_NOT_FOUND;

    for (DWORD i = 0; i < pGroups->GroupCount; i++) {
        if ((pGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
            PSID pSrc = pGroups->Groups[i].Sid;
            DWORD dwSidLen = GetLengthSid(pSrc);

            m_pLogonIdSid = (PSID)LocalAlloc(LPTR, dwSidLen);
            if (!m_pLogonIdSid) {
                fStatus = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }

            if (!CopySid(dwSidLen, m_pLogonIdSid, pSrc)) {
                fStatus = GetLastError();
                LocalFree(m_pLogonIdSid);
                m_pLogonIdSid = nullptr;
                break;
            }

            fStatus = ERROR_SUCCESS;
            break;
        }
    }

    free(pGroups);
    return fStatus;
}

// ============================================================================
// Pipe Name Generation
// ============================================================================

DWORD Broker::GeneratePipeName() {
    HCRYPTPROV hProv = 0;
    BYTE randomBytes[8];

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return GetLastError();

    if (!CryptGenRandom(hProv, sizeof(randomBytes), randomBytes)) {
        DWORD err = GetLastError();
        CryptReleaseContext(hProv, 0);
        return err;
    }
    CryptReleaseContext(hProv, 0);

    WCHAR szHex[17] = {};
    for (int i = 0; i < 8; i++)
        swprintf_s(szHex + i * 2, 3, L"%02X", randomBytes[i]);

    swprintf_s(m_szPipeName, _countof(m_szPipeName),
               L"%s%lu_%s", BROKER_PIPE_PREFIX, GetCurrentProcessId(), szHex);

    return ERROR_SUCCESS;
}

// ============================================================================
// Pipe Security Descriptor
// ============================================================================

DWORD Broker::BuildPipeSecurity() {
    PSID pLowILSid = nullptr;
    DWORD fStatus = ERROR_SUCCESS;

    if (!ConvertStringSidToSid(LOW_IL_STRING_SID, &pLowILSid))
        return GetLastError();

    // Build DACL: grant LogonID SID read+write access
    {
        DWORD dwDaclSize = sizeof(ACL)
            + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(m_pLogonIdSid);

        m_pDacl = (PACL)LocalAlloc(LPTR, dwDaclSize);
        if (!m_pDacl) { fStatus = ERROR_NOT_ENOUGH_MEMORY; goto Cleanup; }

        if (!InitializeAcl(m_pDacl, dwDaclSize, ACL_REVISION))
            { fStatus = GetLastError(); goto Cleanup; }

        if (!AddAccessAllowedAce(m_pDacl, ACL_REVISION,
                                 FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                                 m_pLogonIdSid))
            { fStatus = GetLastError(); goto Cleanup; }
    }

    // Build SACL: Low mandatory integrity label
    {
        DWORD dwSaclSize = sizeof(ACL)
            + sizeof(SYSTEM_MANDATORY_LABEL_ACE) - sizeof(DWORD) + GetLengthSid(pLowILSid);

        m_pSacl = (PACL)LocalAlloc(LPTR, dwSaclSize);
        if (!m_pSacl) { fStatus = ERROR_NOT_ENOUGH_MEMORY; goto Cleanup; }

        if (!InitializeAcl(m_pSacl, dwSaclSize, ACL_REVISION))
            { fStatus = GetLastError(); goto Cleanup; }

        if (!AddMandatoryAce(m_pSacl, ACL_REVISION, 0,
                             SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP,
                             pLowILSid))
            { fStatus = GetLastError(); goto Cleanup; }
    }

    // Assemble security descriptor
    {
        m_pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (!m_pSD) { fStatus = ERROR_NOT_ENOUGH_MEMORY; goto Cleanup; }

        if (!InitializeSecurityDescriptor(m_pSD, SECURITY_DESCRIPTOR_REVISION))
            { fStatus = GetLastError(); goto Cleanup; }

        if (!SetSecurityDescriptorDacl(m_pSD, TRUE, m_pDacl, FALSE))
            { fStatus = GetLastError(); goto Cleanup; }

        if (!SetSecurityDescriptorSacl(m_pSD, TRUE, m_pSacl, FALSE))
            { fStatus = GetLastError(); goto Cleanup; }

        m_sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        m_sa.lpSecurityDescriptor = m_pSD;
        m_sa.bInheritHandle = FALSE;
    }

Cleanup:
    if (pLowILSid) LocalFree(pLowILSid);
    return fStatus;
}

// ============================================================================
// Pipe Instance Creation
// ============================================================================

HANDLE Broker::CreatePipeInstance() {
    return CreateNamedPipe(
        m_szPipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        BROKER_PIPE_BUFFER_SIZE,
        BROKER_PIPE_BUFFER_SIZE,
        0,
        &m_sa);
}

// ============================================================================
// Listener Thread
// ============================================================================

void Broker::ListenerThreadProc(Broker* pBroker) {
    while (true) {
        HANDLE hPipe = pBroker->CreatePipeInstance();
        if (hPipe == INVALID_HANDLE_VALUE) {
            char msg[128];
            sprintf(msg, "Broker: CreateNamedPipe failed with error %lu", GetLastError());
            IssueMessage(msg, MSGTYPE_ERROR);
            return;
        }

        OVERLAPPED ov = {};
        ov.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

        BOOL bConnected = ConnectNamedPipe(hPipe, &ov);
        DWORD dwErr = GetLastError();

        if (!bConnected && dwErr == ERROR_IO_PENDING) {
            HANDLE waitHandles[2] = { ov.hEvent, pBroker->m_hShutdownEvent };
            DWORD dwWait = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

            if (dwWait == WAIT_OBJECT_0 + 1) {
                // Shutdown signaled
                CancelIo(hPipe);
                CloseHandle(ov.hEvent);
                CloseHandle(hPipe);
                return;
            }
        } else if (!bConnected && dwErr != ERROR_PIPE_CONNECTED) {
            CloseHandle(ov.hEvent);
            CloseHandle(hPipe);
            continue;
        }

        CloseHandle(ov.hEvent);

        IssueMessage("Broker: Client connected", MSGTYPE_INFO);

        std::thread clientThread(ClientThreadProc, pBroker, hPipe);
        clientThread.detach();
    }
}

// ============================================================================
// Client Handler Thread
// ============================================================================

void Broker::ClientThreadProc(Broker* pBroker, HANDLE hPipe) {
    BYTE requestBuf[BROKER_MAX_MESSAGE_SIZE];
    BYTE responseBuf[BROKER_MAX_MESSAGE_SIZE];

    while (WaitForSingleObject(pBroker->m_hShutdownEvent, 0) != WAIT_OBJECT_0) {
        // Overlapped read
        OVERLAPPED ov = {};
        ov.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

        DWORD dwBytesRead = 0;
        BOOL bRead = ReadFile(hPipe, requestBuf, sizeof(requestBuf), &dwBytesRead, &ov);
        DWORD dwErr = GetLastError();

        if (!bRead && dwErr == ERROR_IO_PENDING) {
            HANDLE waitHandles[2] = { ov.hEvent, pBroker->m_hShutdownEvent };
            DWORD dwWait = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

            if (dwWait == WAIT_OBJECT_0 + 1) {
                CancelIo(hPipe);
                CloseHandle(ov.hEvent);
                break;
            }

            if (!GetOverlappedResult(hPipe, &ov, &dwBytesRead, FALSE)) {
                CloseHandle(ov.hEvent);
                break;
            }
        } else if (!bRead) {
            CloseHandle(ov.hEvent);
            break;
        }

        CloseHandle(ov.hEvent);

        if (dwBytesRead < sizeof(BrokerMessageHeader))
            continue;

        // Dispatch
        DWORD dwResponseSize = 0;
        pBroker->DispatchRequest(requestBuf, dwBytesRead,
                                 responseBuf, sizeof(responseBuf),
                                 dwResponseSize);

        // Overlapped write
        OVERLAPPED ovWrite = {};
        ovWrite.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        DWORD dwBytesWritten = 0;
        WriteFile(hPipe, responseBuf, dwResponseSize, &dwBytesWritten, &ovWrite);
        GetOverlappedResult(hPipe, &ovWrite, &dwBytesWritten, TRUE);
        CloseHandle(ovWrite.hEvent);
    }

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}

// ============================================================================
// Request Dispatch
// ============================================================================

DWORD Broker::DispatchRequest(const BYTE* pRequestBuf, DWORD dwRequestSize,
                              BYTE* pResponseBuf, DWORD dwResponseBufSize,
                              DWORD& dwResponseSize) {
    auto* pHeader = reinterpret_cast<const BrokerMessageHeader*>(pRequestBuf);
    const BYTE* pPayload = pRequestBuf + sizeof(BrokerMessageHeader);
    DWORD dwPayloadSize = dwRequestSize - sizeof(BrokerMessageHeader);

    // Prepare default error response
    auto* pRespHeader = reinterpret_cast<BrokerResponseHeader*>(pResponseBuf);
    pRespHeader->dwTotalSize = sizeof(BrokerResponseHeader);
    pRespHeader->dwRequestId = pHeader->dwRequestId;
    pRespHeader->dwStatus = ERROR_ACCESS_DENIED;
    pRespHeader->dwHandle = 0;
    dwResponseSize = sizeof(BrokerResponseHeader);

    switch (static_cast<BrokerOperation>(pHeader->dwOperation)) {
        case BROKER_OP_PING:
            return HandlePing(pHeader->dwRequestId, pResponseBuf, dwResponseBufSize, dwResponseSize);

        case BROKER_OP_OPEN_FILE:
            return HandleOpenFile(pPayload, dwPayloadSize, pHeader->dwRequestId,
                                  pHeader->dwProcessId, pResponseBuf, dwResponseBufSize, dwResponseSize);

        case BROKER_OP_DELETE_FILE:
            return HandleDeleteFile(pPayload, dwPayloadSize, pHeader->dwRequestId,
                                    pResponseBuf, dwResponseBufSize, dwResponseSize);

        case BROKER_OP_QUERY_FILE:
            return HandleQueryFile(pPayload, dwPayloadSize, pHeader->dwRequestId,
                                   pResponseBuf, dwResponseBufSize, dwResponseSize);

        case BROKER_OP_OPEN_REG:
            return HandleOpenReg(pPayload, dwPayloadSize, pHeader->dwRequestId,
                                 pHeader->dwProcessId, pResponseBuf, dwResponseBufSize, dwResponseSize);

        case BROKER_OP_QUERY_REG:
            return HandleQueryReg(pPayload, dwPayloadSize, pHeader->dwRequestId,
                                  pResponseBuf, dwResponseBufSize, dwResponseSize);

        case BROKER_OP_WRITE_REG:
            return HandleWriteReg(pPayload, dwPayloadSize, pHeader->dwRequestId,
                                  pResponseBuf, dwResponseBufSize, dwResponseSize);

        case BROKER_OP_OPEN_PROCESS:
            return HandleOpenProcess(pPayload, dwPayloadSize, pHeader->dwRequestId,
                                     pHeader->dwProcessId, pResponseBuf, dwResponseBufSize, dwResponseSize);

        case BROKER_OP_TRACE:
            return HandleTrace(pPayload, dwPayloadSize, pHeader->dwRequestId,
                               pHeader->dwProcessId, pResponseBuf, dwResponseBufSize, dwResponseSize);

        default:
            return ERROR_INVALID_FUNCTION;
    }
}

// ============================================================================
// Path Validation
// ============================================================================

BOOL Broker::ValidatePath(LPCWSTR szPath, WCHAR* szCanonical, DWORD cchCanonical) {
    if (!szPath || !szPath[0])
        return FALSE;

    // Reject device-path prefixes that bypass Win32 normalization
    if (wcsncmp(szPath, L"\\\\?\\", 4) == 0 || wcsncmp(szPath, L"\\\\.\\", 4) == 0)
        return FALSE;

    DWORD dwLen = GetFullPathName(szPath, cchCanonical, szCanonical, nullptr);
    if (dwLen == 0 || dwLen >= cchCanonical)
        return FALSE;

    return TRUE;
}

HKEY Broker::RootKeyFromId(DWORD dwRootKey) {
    switch (dwRootKey) {
        case 0: return HKEY_LOCAL_MACHINE;
        case 1: return HKEY_CURRENT_USER;
        case 2: return HKEY_CLASSES_ROOT;
        case 3: return HKEY_USERS;
        default: return nullptr;
    }
}

// ============================================================================
// Operation Handlers
// ============================================================================

DWORD Broker::HandlePing(DWORD dwRequestId, BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize) {
    auto* pRespHeader = reinterpret_cast<BrokerResponseHeader*>(pResp);
    pRespHeader->dwTotalSize = sizeof(BrokerResponseHeader);
    pRespHeader->dwRequestId = dwRequestId;
    pRespHeader->dwStatus = ERROR_SUCCESS;
    pRespHeader->dwHandle = 0;
    dwRespSize = sizeof(BrokerResponseHeader);
    return ERROR_SUCCESS;
}

DWORD Broker::HandleOpenFile(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                             DWORD dwCallerPid, BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize) {
    auto* pRespHeader = reinterpret_cast<BrokerResponseHeader*>(pResp);

    // Validate payload
    if (dwPayloadSize < offsetof(OpenFileRequestPayload, szPath))
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    auto* pReq = reinterpret_cast<const OpenFileRequestPayload*>(pPayload);
    DWORD dwPathBytes = pReq->dwPathLengthBytes;

    if (dwPathBytes > dwPayloadSize - offsetof(OpenFileRequestPayload, szPath))
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    DWORD dwPathChars = dwPathBytes / sizeof(WCHAR);
    if (dwPathChars == 0 || pReq->szPath[dwPathChars - 1] != L'\0')
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    // Canonicalize path
    WCHAR szCanonical[MAX_PATH];
    if (!ValidatePath(pReq->szPath, szCanonical, MAX_PATH))
        { pRespHeader->dwStatus = ERROR_BAD_PATHNAME; return ERROR_BAD_PATHNAME; }

    // Policy check
    if (!m_policy.IsAllowed(BROKER_OP_OPEN_FILE, szCanonical)) {
        pRespHeader->dwStatus = ERROR_ACCESS_DENIED;
        // LogBrokerFailure("OPEN_FILE", "policy denied", szCanonical, ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }

    // Impersonate and open
    if (!ImpersonateLoggedOnUser(m_hBrokerToken))
        { pRespHeader->dwStatus = GetLastError(); return pRespHeader->dwStatus; }

    HANDLE hFile = CreateFile(szCanonical, pReq->dwDesiredAccess, pReq->dwShareMode,
                              nullptr, pReq->dwCreationDisposition,
                              pReq->dwFlagsAndAttributes, nullptr);
    DWORD fStatus = (hFile != INVALID_HANDLE_VALUE) ? ERROR_SUCCESS : GetLastError();

    RevertToSelf();

    if (fStatus != ERROR_SUCCESS) {
        pRespHeader->dwStatus = fStatus;
        // LogBrokerFailure("OPEN_FILE", "CreateFile failed", szCanonical, fStatus);
        return fStatus;
    }

    // Duplicate handle into caller's process
    HANDLE hCallerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwCallerPid);
    if (!hCallerProcess) {
        fStatus = GetLastError();
        CloseHandle(hFile);
        pRespHeader->dwStatus = fStatus;
        // LogBrokerFailure("OPEN_FILE", "OpenProcess caller failed", szCanonical, fStatus);
        return fStatus;
    }

    HANDLE hDup = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), hFile, hCallerProcess, &hDup,
                         0, FALSE, DUPLICATE_SAME_ACCESS)) {
        fStatus = GetLastError();
        // LogBrokerFailure("OPEN_FILE", "DuplicateHandle failed", szCanonical, fStatus);
    }

    CloseHandle(hFile);
    CloseHandle(hCallerProcess);

    // LogBrokerFailure("OPEN_FILE", fStatus == ERROR_SUCCESS ? "policy allowed" : "DuplicateHandle failed",
    //                  szCanonical, fStatus);

    pRespHeader->dwTotalSize = sizeof(BrokerResponseHeader);
    pRespHeader->dwRequestId = dwRequestId;
    pRespHeader->dwStatus = fStatus;
    pRespHeader->dwHandle = (DWORD_PTR)hDup;
    dwRespSize = sizeof(BrokerResponseHeader);

    return fStatus;
}

DWORD Broker::HandleDeleteFile(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                               BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize) {
    auto* pRespHeader = reinterpret_cast<BrokerResponseHeader*>(pResp);

    if (dwPayloadSize < offsetof(DeleteFileRequestPayload, szPath))
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    auto* pReq = reinterpret_cast<const DeleteFileRequestPayload*>(pPayload);
    DWORD dwPathChars = pReq->dwPathLengthBytes / sizeof(WCHAR);
    if (dwPathChars == 0 || pReq->szPath[dwPathChars - 1] != L'\0')
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    WCHAR szCanonical[MAX_PATH];
    if (!ValidatePath(pReq->szPath, szCanonical, MAX_PATH))
        { pRespHeader->dwStatus = ERROR_BAD_PATHNAME; return ERROR_BAD_PATHNAME; }

    if (!m_policy.IsAllowed(BROKER_OP_DELETE_FILE, szCanonical)) {
        pRespHeader->dwStatus = ERROR_ACCESS_DENIED;
        // LogBrokerFailure("DELETE_FILE", "policy denied", szCanonical, ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }

    if (!ImpersonateLoggedOnUser(m_hBrokerToken))
        { pRespHeader->dwStatus = GetLastError(); return pRespHeader->dwStatus; }

    DWORD fStatus = ::DeleteFile(szCanonical) ? ERROR_SUCCESS : GetLastError();

    RevertToSelf();

    if (fStatus != ERROR_SUCCESS)
        // LogBrokerFailure("DELETE_FILE", "DeleteFile failed", szCanonical, fStatus);

    pRespHeader->dwTotalSize = sizeof(BrokerResponseHeader);
    pRespHeader->dwRequestId = dwRequestId;
    pRespHeader->dwStatus = fStatus;
    pRespHeader->dwHandle = 0;
    dwRespSize = sizeof(BrokerResponseHeader);

    return fStatus;
}

DWORD Broker::HandleQueryFile(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                              BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize) {
    auto* pRespHeader = reinterpret_cast<BrokerResponseHeader*>(pResp);

    if (dwPayloadSize < offsetof(QueryFileRequestPayload, szPath))
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    auto* pReq = reinterpret_cast<const QueryFileRequestPayload*>(pPayload);
    DWORD dwPathChars = pReq->dwPathLengthBytes / sizeof(WCHAR);
    if (dwPathChars == 0 || pReq->szPath[dwPathChars - 1] != L'\0')
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    WCHAR szCanonical[MAX_PATH];
    if (!ValidatePath(pReq->szPath, szCanonical, MAX_PATH))
        { pRespHeader->dwStatus = ERROR_BAD_PATHNAME; return ERROR_BAD_PATHNAME; }

    if (!m_policy.IsAllowed(BROKER_OP_QUERY_FILE, szCanonical)) {
        pRespHeader->dwStatus = ERROR_ACCESS_DENIED;
        // LogBrokerFailure("QUERY_FILE", "policy denied", szCanonical, ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }

    if (!ImpersonateLoggedOnUser(m_hBrokerToken))
        { pRespHeader->dwStatus = GetLastError(); return pRespHeader->dwStatus; }

    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    DWORD fStatus = GetFileAttributesEx(szCanonical, GetFileExInfoStandard, &fad)
                    ? ERROR_SUCCESS : GetLastError();

    RevertToSelf();

    if (fStatus != ERROR_SUCCESS)
        // LogBrokerFailure("QUERY_FILE", "GetFileAttributesEx failed", szCanonical, fStatus);

    pRespHeader->dwTotalSize = sizeof(BrokerResponseHeader);
    pRespHeader->dwRequestId = dwRequestId;
    pRespHeader->dwStatus = fStatus;
    pRespHeader->dwHandle = 0;

    if (fStatus == ERROR_SUCCESS) {
        auto* pRespPayload = reinterpret_cast<QueryFileResponsePayload*>(
            pResp + sizeof(BrokerResponseHeader));

        pRespPayload->dwFileAttributes = fad.dwFileAttributes;
        pRespPayload->ullFileSize = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        pRespPayload->ftCreationTime = fad.ftCreationTime;
        pRespPayload->ftLastWriteTime = fad.ftLastWriteTime;

        dwRespSize = sizeof(BrokerResponseHeader) + sizeof(QueryFileResponsePayload);
        pRespHeader->dwTotalSize = dwRespSize;
    } else {
        dwRespSize = sizeof(BrokerResponseHeader);
    }

    return fStatus;
}

DWORD Broker::HandleOpenReg(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                            DWORD dwCallerPid, BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize) {
    auto* pRespHeader = reinterpret_cast<BrokerResponseHeader*>(pResp);

    if (dwPayloadSize < offsetof(OpenRegRequestPayload, szSubKey))
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    auto* pReq = reinterpret_cast<const OpenRegRequestPayload*>(pPayload);
    DWORD dwSubKeyChars = pReq->dwSubKeyLengthBytes / sizeof(WCHAR);
    if (dwSubKeyChars == 0 || pReq->szSubKey[dwSubKeyChars - 1] != L'\0')
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    HKEY hRootKey = RootKeyFromId(pReq->dwRootKey);
    if (!hRootKey)
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    // Policy check using the full registry path
    WCHAR szFullRegPath[512];
    const WCHAR* rootNames[] = { L"HKLM\\", L"HKCU\\", L"HKCR\\", L"HKU\\" };
    swprintf_s(szFullRegPath, _countof(szFullRegPath), L"%s%s",
               rootNames[pReq->dwRootKey], pReq->szSubKey);

    if (!m_policy.IsAllowed(BROKER_OP_OPEN_REG, szFullRegPath)) {
        pRespHeader->dwStatus = ERROR_ACCESS_DENIED;
        // LogBrokerFailure("OPEN_REG", "policy denied", szFullRegPath, ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }

    if (!ImpersonateLoggedOnUser(m_hBrokerToken))
        { pRespHeader->dwStatus = GetLastError(); return pRespHeader->dwStatus; }

    HKEY hKey = nullptr;
    DWORD fStatus = RegOpenKeyEx(hRootKey, pReq->szSubKey, 0, pReq->dwDesiredAccess, &hKey);

    RevertToSelf();

    if (fStatus != ERROR_SUCCESS) {
        pRespHeader->dwStatus = fStatus;
        // LogBrokerFailure("OPEN_REG", "RegOpenKeyEx failed", szFullRegPath, fStatus);
        return fStatus;
    }

    // Duplicate the key handle into the caller's process
    HANDLE hCallerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwCallerPid);
    if (!hCallerProcess) {
        fStatus = GetLastError();
        RegCloseKey(hKey);
        pRespHeader->dwStatus = fStatus;
        // LogBrokerFailure("OPEN_REG", "OpenProcess caller failed", szFullRegPath, fStatus);
        return fStatus;
    }

    HANDLE hDup = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)hKey, hCallerProcess, &hDup,
                         0, FALSE, DUPLICATE_SAME_ACCESS)) {
        fStatus = GetLastError();
        // LogBrokerFailure("OPEN_REG", "DuplicateHandle failed", szFullRegPath, fStatus);
    }

    RegCloseKey(hKey);
    CloseHandle(hCallerProcess);

    pRespHeader->dwTotalSize = sizeof(BrokerResponseHeader);
    pRespHeader->dwRequestId = dwRequestId;
    pRespHeader->dwStatus = fStatus;
    pRespHeader->dwHandle = (DWORD_PTR)hDup;
    dwRespSize = sizeof(BrokerResponseHeader);

    return fStatus;
}

DWORD Broker::HandleQueryReg(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                             BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize) {
    auto* pRespHeader = reinterpret_cast<BrokerResponseHeader*>(pResp);

    if (dwPayloadSize < offsetof(QueryRegRequestPayload, szData))
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    auto* pReq = reinterpret_cast<const QueryRegRequestPayload*>(pPayload);

    // Extract subkey and value name from the packed data
    DWORD dwSubKeyChars = pReq->dwSubKeyLengthBytes / sizeof(WCHAR);
    DWORD dwValueNameChars = pReq->dwValueNameLengthBytes / sizeof(WCHAR);
    DWORD dwTotalChars = dwSubKeyChars + dwValueNameChars;
    DWORD dwAvailChars = (dwPayloadSize - offsetof(QueryRegRequestPayload, szData)) / sizeof(WCHAR);

    if (dwTotalChars > dwAvailChars || dwSubKeyChars == 0 || dwValueNameChars == 0)
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    LPCWSTR szSubKey = pReq->szData;
    LPCWSTR szValueName = pReq->szData + dwSubKeyChars;

    if (szSubKey[dwSubKeyChars - 1] != L'\0' || szValueName[dwValueNameChars - 1] != L'\0')
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    HKEY hRootKey = RootKeyFromId(pReq->dwRootKey);
    if (!hRootKey)
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    // Policy check
    WCHAR szFullRegPath[512];
    const WCHAR* rootNames[] = { L"HKLM\\", L"HKCU\\", L"HKCR\\", L"HKU\\" };
    swprintf_s(szFullRegPath, _countof(szFullRegPath), L"%s%s",
               rootNames[pReq->dwRootKey], szSubKey);

    if (!m_policy.IsAllowed(BROKER_OP_QUERY_REG, szFullRegPath)) {
        pRespHeader->dwStatus = ERROR_ACCESS_DENIED;
        // LogBrokerFailure("QUERY_REG", "policy denied", szFullRegPath, ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }

    if (!ImpersonateLoggedOnUser(m_hBrokerToken))
        { pRespHeader->dwStatus = GetLastError(); return pRespHeader->dwStatus; }

    HKEY hKey = nullptr;
    DWORD fStatus = RegOpenKeyEx(hRootKey, szSubKey, 0, KEY_READ, &hKey);

    if (fStatus == ERROR_SUCCESS) {
        auto* pRespPayload = reinterpret_cast<QueryRegResponsePayload*>(
            pResp + sizeof(BrokerResponseHeader));

        DWORD dwType = 0;
        DWORD dwDataSize = dwRespBufSize - sizeof(BrokerResponseHeader)
                           - offsetof(QueryRegResponsePayload, data);

        fStatus = RegQueryValueEx(hKey, szValueName, nullptr, &dwType,
                                  pRespPayload->data, &dwDataSize);

        if (fStatus != ERROR_SUCCESS)
            ; // LogBrokerFailure("QUERY_REG", "RegQueryValueEx failed", szFullRegPath, fStatus);

        if (fStatus == ERROR_SUCCESS) {
            pRespPayload->dwRegType = dwType;
            pRespPayload->dwDataSize = dwDataSize;
            dwRespSize = sizeof(BrokerResponseHeader) + offsetof(QueryRegResponsePayload, data) + dwDataSize;
        }

        RegCloseKey(hKey);
    }

    RevertToSelf();

    pRespHeader->dwTotalSize = dwRespSize;
    pRespHeader->dwRequestId = dwRequestId;
    pRespHeader->dwStatus = fStatus;
    pRespHeader->dwHandle = 0;

    return fStatus;
}

DWORD Broker::HandleWriteReg(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                             BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize) {
    auto* pRespHeader = reinterpret_cast<BrokerResponseHeader*>(pResp);

    if (dwPayloadSize < offsetof(WriteRegRequestPayload, szData))
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    auto* pReq = reinterpret_cast<const WriteRegRequestPayload*>(pPayload);

    DWORD dwSubKeyChars = pReq->dwSubKeyLengthBytes / sizeof(WCHAR);
    DWORD dwValueNameChars = pReq->dwValueNameLengthBytes / sizeof(WCHAR);
    DWORD dwMinPayload = offsetof(WriteRegRequestPayload, szData)
                         + pReq->dwSubKeyLengthBytes + pReq->dwValueNameLengthBytes + pReq->dwDataSize;

    if (dwPayloadSize < dwMinPayload || dwSubKeyChars == 0 || dwValueNameChars == 0)
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    LPCWSTR szSubKey = pReq->szData;
    LPCWSTR szValueName = pReq->szData + dwSubKeyChars;
    const BYTE* pData = reinterpret_cast<const BYTE*>(pReq->szData + dwSubKeyChars + dwValueNameChars);

    if (szSubKey[dwSubKeyChars - 1] != L'\0' || szValueName[dwValueNameChars - 1] != L'\0')
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    HKEY hRootKey = RootKeyFromId(pReq->dwRootKey);
    if (!hRootKey)
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    WCHAR szFullRegPath[512];
    const WCHAR* rootNames[] = { L"HKLM\\", L"HKCU\\", L"HKCR\\", L"HKU\\" };
    swprintf_s(szFullRegPath, _countof(szFullRegPath), L"%s%s",
               rootNames[pReq->dwRootKey], szSubKey);

    if (!m_policy.IsAllowed(BROKER_OP_WRITE_REG, szFullRegPath)) {
        pRespHeader->dwStatus = ERROR_ACCESS_DENIED;
        // LogBrokerFailure("WRITE_REG", "policy denied", szFullRegPath, ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }

    if (!ImpersonateLoggedOnUser(m_hBrokerToken))
        { pRespHeader->dwStatus = GetLastError(); return pRespHeader->dwStatus; }

    HKEY hKey = nullptr;
    DWORD fStatus = RegOpenKeyEx(hRootKey, szSubKey, 0, KEY_WRITE, &hKey);

    if (fStatus == ERROR_SUCCESS) {
        fStatus = RegSetValueEx(hKey, szValueName, 0, pReq->dwRegType, pData, pReq->dwDataSize);
        if (fStatus != ERROR_SUCCESS)
            ; // LogBrokerFailure("WRITE_REG", "RegSetValueEx failed", szFullRegPath, fStatus);
        RegCloseKey(hKey);
    } else {
        ; // LogBrokerFailure("WRITE_REG", "RegOpenKeyEx failed", szFullRegPath, fStatus);
    }

    RevertToSelf();

    pRespHeader->dwTotalSize = sizeof(BrokerResponseHeader);
    pRespHeader->dwRequestId = dwRequestId;
    pRespHeader->dwStatus = fStatus;
    pRespHeader->dwHandle = 0;
    dwRespSize = sizeof(BrokerResponseHeader);

    return fStatus;
}

DWORD Broker::HandleOpenProcess(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                                DWORD dwCallerPid, BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize) {
    auto* pRespHeader = reinterpret_cast<BrokerResponseHeader*>(pResp);

    if (dwPayloadSize < sizeof(OpenProcessRequestPayload))
        { pRespHeader->dwStatus = ERROR_INVALID_PARAMETER; return ERROR_INVALID_PARAMETER; }

    auto* pReq = reinterpret_cast<const OpenProcessRequestPayload*>(pPayload);

    // Policy check — use PID as a string for the path pattern
    WCHAR szPidStr[32];
    swprintf_s(szPidStr, _countof(szPidStr), L"%lu", pReq->dwTargetProcessId);

    if (!m_policy.IsAllowed(BROKER_OP_OPEN_PROCESS, szPidStr)) {
        pRespHeader->dwStatus = ERROR_ACCESS_DENIED;
        // LogBrokerFailure("OPEN_PROCESS", "policy denied", szPidStr, ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }

    if (!ImpersonateLoggedOnUser(m_hBrokerToken))
        { pRespHeader->dwStatus = GetLastError(); return pRespHeader->dwStatus; }

    HANDLE hTarget = OpenProcess(pReq->dwDesiredAccess, FALSE, pReq->dwTargetProcessId);
    DWORD fStatus = hTarget ? ERROR_SUCCESS : GetLastError();

    RevertToSelf();

    if (fStatus != ERROR_SUCCESS) {
        pRespHeader->dwStatus = fStatus;
        // LogBrokerFailure("OPEN_PROCESS", "OpenProcess target failed", szPidStr, fStatus);
        return fStatus;
    }

    // Duplicate into caller
    HANDLE hCallerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwCallerPid);
    if (!hCallerProcess) {
        fStatus = GetLastError();
        CloseHandle(hTarget);
        pRespHeader->dwStatus = fStatus;
        // LogBrokerFailure("OPEN_PROCESS", "OpenProcess caller failed", szPidStr, fStatus);
        return fStatus;
    }

    HANDLE hDup = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), hTarget, hCallerProcess, &hDup,
                         0, FALSE, DUPLICATE_SAME_ACCESS)) {
        fStatus = GetLastError();
        // LogBrokerFailure("OPEN_PROCESS", "DuplicateHandle failed", szPidStr, fStatus);
    }

    CloseHandle(hTarget);
    CloseHandle(hCallerProcess);

    pRespHeader->dwTotalSize = sizeof(BrokerResponseHeader);
    pRespHeader->dwRequestId = dwRequestId;
    pRespHeader->dwStatus = fStatus;
    pRespHeader->dwHandle = (DWORD_PTR)hDup;
    dwRespSize = sizeof(BrokerResponseHeader);

    return fStatus;
}

DWORD Broker::HandleTrace(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                          DWORD dwCallerPid, BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize) {
    auto* pRespHeader = reinterpret_cast<BrokerResponseHeader*>(pResp);

    if (dwPayloadSize < offsetof(TraceRequestPayload, szMessage)) {
        pRespHeader->dwStatus = ERROR_INVALID_PARAMETER;
        return ERROR_INVALID_PARAMETER;
    }

    auto* pReq = reinterpret_cast<const TraceRequestPayload*>(pPayload);
    if (pReq->dwMessageLengthBytes == 0 ||
        pReq->dwMessageLengthBytes > dwPayloadSize - offsetof(TraceRequestPayload, szMessage)) {
        pRespHeader->dwStatus = ERROR_INVALID_PARAMETER;
        return ERROR_INVALID_PARAMETER;
    }

    DWORD msgLen = pReq->dwMessageLengthBytes;
    char message[1024] = {};
    size_t copyLen = msgLen;
    if (copyLen >= sizeof(message))
        copyLen = sizeof(message) - 1;

    memcpy(message, pReq->szMessage, copyLen);
    message[copyLen] = '\0';

    char fullMessage[1200] = {};
    sprintf_s(fullMessage, "Broker trace from pid=%lu: %s", dwCallerPid, message);
    IssueMessage(fullMessage, MSGTYPE_INFO);

    pRespHeader->dwTotalSize = sizeof(BrokerResponseHeader);
    pRespHeader->dwRequestId = dwRequestId;
    pRespHeader->dwStatus = ERROR_SUCCESS;
    pRespHeader->dwHandle = 0;
    dwRespSize = sizeof(BrokerResponseHeader);

    return ERROR_SUCCESS;
}
