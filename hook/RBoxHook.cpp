//
// RBoxHook.cpp — Hook DLL implementation.
//

#include "RBoxHook.h"
#include <cstdarg>
#include <cstdio>
#include <cstring>

// ============================================================================
// Globals
// ============================================================================

HMODULE g_hModule = nullptr;
WCHAR   g_szHookDllPath[MAX_PATH] = {};
HookBrokerClient g_client;
__declspec(thread) BOOL g_bInBrokerCall = FALSE;
static __declspec(thread) BOOL g_bSpawningHelper = FALSE;
static __declspec(thread) BOOL g_bInHookTrace = FALSE;

struct PendingChildHook {
    HANDLE hProcess;
    DWORD  dwThreadId;
};

static const int MAX_PENDING_CHILDREN = 64;
static CRITICAL_SECTION g_pendingChildrenLock;
static bool g_pendingChildrenLockInitialized = false;
static PendingChildHook g_pendingChildren[MAX_PENDING_CHILDREN] = {};

// Trampoline pointers — callable originals
static pfnNtCreateFile           Original_NtCreateFile = nullptr;
static pfnNtOpenFile             Original_NtOpenFile = nullptr;
static pfnNtDeleteFile           Original_NtDeleteFile = nullptr;
static pfnNtQueryAttributesFile  Original_NtQueryAttributesFile = nullptr;
static pfnNtQueryFullAttributesFile Original_NtQueryFullAttributesFile = nullptr;
static pfnNtOpenKey              Original_NtOpenKey = nullptr;
static pfnNtOpenKeyEx            Original_NtOpenKeyEx = nullptr;
static pfnNtCreateKey            Original_NtCreateKey = nullptr;
static pfnNtQueryValueKey        Original_NtQueryValueKey = nullptr;
static pfnNtSetValueKey          Original_NtSetValueKey = nullptr;
static pfnNtDeleteKey            Original_NtDeleteKey = nullptr;
static pfnNtOpenProcess          Original_NtOpenProcess = nullptr;
static pfnNtCreateUserProcess    Original_NtCreateUserProcess = nullptr;
static pfnNtResumeThread         Original_NtResumeThread = nullptr;
static pfnNtWriteFile            Original_NtWriteFile = nullptr;
static pfnNtReadFile             Original_NtReadFile = nullptr;
static pfnNtQueryObject          s_NtQueryObject = nullptr;

// Hook entries for cleanup
static HookEntry g_hooks[16];
static DWORD g_hookCount = 0;

static void HookTrace(const char* format, ...) {
    if (g_bInHookTrace)
        return;

    g_bInHookTrace = TRUE;

    char payload[1024];
    va_list args;
    va_start(args, format);
    vsnprintf_s(payload, sizeof(payload), _TRUNCATE, format, args);
    va_end(args);

    char message[1200];
    _snprintf_s(message, sizeof(message), _TRUNCATE, "[pid=%lu] %s", GetCurrentProcessId(), payload);

    OutputDebugStringA(message);
    OutputDebugStringA("\n");
    g_client.Trace(message);

    g_bInHookTrace = FALSE;
}

static void InitializePendingChildrenState() {
    if (!g_pendingChildrenLockInitialized) {
        InitializeCriticalSection(&g_pendingChildrenLock);
        g_pendingChildrenLockInitialized = true;
    }
}

static void DestroyPendingChildrenState() {
    if (g_pendingChildrenLockInitialized) {
        DeleteCriticalSection(&g_pendingChildrenLock);
        g_pendingChildrenLockInitialized = false;
    }
}

static bool AddPendingChild(HANDLE hProcess, HANDLE hThread) {
    if (!g_pendingChildrenLockInitialized || !hProcess || !hThread)
        return false;

    DWORD dwThreadId = GetThreadId(hThread);
    if (dwThreadId == 0)
        return false;

    EnterCriticalSection(&g_pendingChildrenLock);
    for (int i = 0; i < MAX_PENDING_CHILDREN; ++i) {
        if (!g_pendingChildren[i].hProcess) {
            g_pendingChildren[i].hProcess = hProcess;
            g_pendingChildren[i].dwThreadId = dwThreadId;
            LeaveCriticalSection(&g_pendingChildrenLock);
            return true;
        }
    }
    LeaveCriticalSection(&g_pendingChildrenLock);

    return false;
}

static HANDLE TakePendingChildByThread(HANDLE hThread) {
    if (!g_pendingChildrenLockInitialized || !hThread)
        return nullptr;

    DWORD dwThreadId = GetThreadId(hThread);
    if (dwThreadId == 0)
        return nullptr;

    EnterCriticalSection(&g_pendingChildrenLock);
    for (int i = 0; i < MAX_PENDING_CHILDREN; ++i) {
        if (g_pendingChildren[i].hProcess && g_pendingChildren[i].dwThreadId == dwThreadId) {
            HANDLE hProcess = g_pendingChildren[i].hProcess;
            g_pendingChildren[i].hProcess  = nullptr;
            g_pendingChildren[i].dwThreadId = 0;
            LeaveCriticalSection(&g_pendingChildrenLock);
            return hProcess;
        }
    }
    LeaveCriticalSection(&g_pendingChildrenLock);

    return nullptr;
}

// ============================================================================
// NT Path Extraction
// ============================================================================

// Extract the full NT path from an OBJECT_ATTRIBUTES into a null-terminated
// buffer.  When RootDirectory is set (relative path), resolves the root name
// and combines it with ObjectName.  bFileHandle controls the resolution strategy:
// file handles use GetFinalPathNameByHandleW, registry handles use NtQueryObject.
// Returns FALSE on overflow or unresolvable paths — the hook then falls back to
// the original (denied) status, which is safe.

static BOOL OaToNtPath(POBJECT_ATTRIBUTES oa, LPWSTR szOut, DWORD cchOut, BOOL bFileHandle) {
    if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer)
        return FALSE;

    USHORT nRelChars = oa->ObjectName->Length / sizeof(WCHAR);

    if (!oa->RootDirectory) {
        // Absolute path — just copy ObjectName
        if (nRelChars == 0 || nRelChars >= cchOut)
            return FALSE;
        memcpy(szOut, oa->ObjectName->Buffer, nRelChars * sizeof(WCHAR));
        szOut[nRelChars] = L'\0';
        return TRUE;
    }

    // Relative path — resolve RootDirectory to get a full NT namespace path
    WCHAR szRoot[MAX_PATH];
    DWORD nRootChars = 0;

    if (bFileHandle) {
        // For file handles, GetFinalPathNameByHandleW returns \\?\C:\... which we
        // convert to \??\C:\... (NT DosDevices prefix).
        g_bInBrokerCall = TRUE;
        DWORD len = GetFinalPathNameByHandleW(oa->RootDirectory, szRoot, MAX_PATH,
                                               VOLUME_NAME_DOS);
        g_bInBrokerCall = FALSE;

        if (len == 0 || len >= MAX_PATH)
            return FALSE;

        // \\?\C:\path → \??\C:\path  (replace second backslash with '?')
        if (len >= 4 && szRoot[0] == L'\\' && szRoot[1] == L'\\' &&
            szRoot[2] == L'?' && szRoot[3] == L'\\') {
            szRoot[1] = L'?';
        }
        nRootChars = len;
    } else {
        // For registry key handles, NtQueryObject(ObjectNameInformation) returns
        // the full NT path: \REGISTRY\MACHINE\SOFTWARE\...
        if (!s_NtQueryObject)
            return FALSE;

        BYTE buf[2048];
        ULONG cbResult = 0;
        g_bInBrokerCall = TRUE;
        NTSTATUS status = s_NtQueryObject(oa->RootDirectory, ObjectNameInformation,
                                           buf, sizeof(buf), &cbResult);
        g_bInBrokerCall = FALSE;

        if (status != 0)
            return FALSE;

        // OBJECT_NAME_INFORMATION starts with a UNICODE_STRING
        auto* pName = reinterpret_cast<UNICODE_STRING*>(buf);
        nRootChars = pName->Length / sizeof(WCHAR);
        if (nRootChars == 0 || nRootChars >= MAX_PATH)
            return FALSE;

        memcpy(szRoot, pName->Buffer, nRootChars * sizeof(WCHAR));
        szRoot[nRootChars] = L'\0';
    }

    // Combine: root + "\" + relative
    BOOL needSep = (nRootChars > 0 && szRoot[nRootChars - 1] != L'\\' &&
                    nRelChars > 0 && oa->ObjectName->Buffer[0] != L'\\');
    DWORD totalChars = nRootChars + (needSep ? 1 : 0) + nRelChars;
    if (totalChars >= cchOut)
        return FALSE;

    memcpy(szOut, szRoot, nRootChars * sizeof(WCHAR));
    DWORD pos = nRootChars;
    if (needSep) szOut[pos++] = L'\\';
    memcpy(szOut + pos, oa->ObjectName->Buffer, nRelChars * sizeof(WCHAR));
    szOut[pos + nRelChars] = L'\0';
    return TRUE;
}

// Returns TRUE if the resolved NT path is a file-system path that the broker
// can handle (\??\..., \DosDevices\...).  Device paths (\Device\CNG, etc.)
// and other kernel object paths are not brokerable.
static BOOL IsBrokerablePath(LPCWSTR szNtPath) {
    if (!szNtPath) return FALSE;
    if (_wcsnicmp(szNtPath, L"\\??\\", 4) == 0) return TRUE;
    if (_wcsnicmp(szNtPath, L"\\DosDevices\\", 12) == 0) return TRUE;
    return FALSE;
}

// ============================================================================
// DLL Injection Helper (for subprocess propagation)
// ============================================================================

static DWORD InjectHookDll(HANDLE hProcess, LPCWSTR szDllPath) {
    HookTrace("InjectHookDll start targetProcess=%p dll=%ls", hProcess, szDllPath ? szDllPath : L"<null>");

    SIZE_T dwSize = (lstrlenW(szDllPath) + 1) * sizeof(WCHAR);
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, nullptr, dwSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf) {
        HookTrace("InjectHookDll VirtualAllocEx failed status=%lu", GetLastError());
        return GetLastError();
    }

    if (!WriteProcessMemory(hProcess, pRemoteBuf, szDllPath, dwSize, nullptr)) {
        HookTrace("InjectHookDll WriteProcessMemory failed status=%lu", GetLastError());
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return GetLastError();
    }

    auto pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibrary, pRemoteBuf, 0, nullptr);
    if (!hThread) {
        DWORD err = GetLastError();
        HookTrace("InjectHookDll CreateRemoteThread failed status=%lu", err);
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return err;
    }

    DWORD waitResult = WaitForSingleObject(hThread, 5000);
    DWORD remoteExitCode = 0;
    GetExitCodeThread(hThread, &remoteExitCode);
    HookTrace("InjectHookDll thread waitResult=%lu remoteExitCode=%lu", waitResult, remoteExitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    HookTrace("InjectHookDll success");
    return ERROR_SUCCESS;
}

// ============================================================================
// Cross-Architecture Injection
// ============================================================================

static BOOL IsChildSameArchitecture(HANDLE hProcess) {
    BOOL bChildIsWow64 = FALSE;
    IsWow64Process(hProcess, &bChildIsWow64);

#ifdef _WIN64
    // We're 64-bit. Child is same arch if it's NOT WoW64 (also 64-bit).
    return !bChildIsWow64;
#else
    // We're 32-bit. If we're on a 64-bit OS (we ourselves are WoW64),
    // a child that is NOT WoW64 is a 64-bit process → cross-arch.
    BOOL bWeAreWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &bWeAreWow64);
    if (!bWeAreWow64) {
        // Native 32-bit OS — all processes are 32-bit.
        return TRUE;
    }
    // 32-bit on 64-bit OS. Same arch if child is also WoW64 (32-bit).
    return bChildIsWow64;
#endif
}

static DWORD InjectHookDllCrossArch(HANDLE hProcess) {
    HookTrace("InjectHookDllCrossArch start targetProcess=%p", hProcess);

    // Derive the cross-arch DLL and helper paths from our DLL's directory
    WCHAR szDir[MAX_PATH];
    wcscpy_s(szDir, g_szHookDllPath);
    WCHAR *pSlash = wcsrchr(szDir, L'\\');
    if (!pSlash) {
        HookTrace("InjectHookDllCrossArch failed status=%lu", ERROR_PATH_NOT_FOUND);
        return ERROR_PATH_NOT_FOUND;
    }
    *(pSlash + 1) = L'\0';

    WCHAR szCrossDll[MAX_PATH];
    wcscpy_s(szCrossDll, szDir);

    WCHAR szHelper[MAX_PATH];
    wcscpy_s(szHelper, szDir);

#ifdef _WIN64
    wcscat_s(szCrossDll, L"RBoxHook32.dll");
    wcscat_s(szHelper, L"RBoxInject32.exe");
#else
    wcscat_s(szCrossDll, L"RBoxHook64.dll");
    wcscat_s(szHelper, L"RBoxInject64.exe");
#endif

    // Make the target process handle inheritable so the helper can use it
    SetHandleInformation(hProcess, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    // Build command line: RBoxInject.exe <handle_value> "<DLL path>"
    WCHAR szCmdLine[MAX_PATH * 2];
    _snwprintf_s(szCmdLine, _TRUNCATE, L"\"%s\" %llu \"%s\"",
                 szHelper, (unsigned long long)(ULONG_PTR)hProcess, szCrossDll);

    STARTUPINFO si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);

    // Set flag to prevent our NtCreateUserProcess hook from injecting into the helper
    g_bSpawningHelper = TRUE;
    BOOL bOk = CreateProcess(szHelper, szCmdLine, nullptr, nullptr,
                             TRUE, // bInheritHandles — helper inherits target handle
                             0, nullptr, nullptr, &si, &pi);
    g_bSpawningHelper = FALSE;

    if (!bOk) {
        HookTrace("InjectHookDllCrossArch CreateProcess helper failed status=%lu", GetLastError());
        return GetLastError();
    }

    WaitForSingleObject(pi.hProcess, 10000);

    DWORD dwExitCode = 0;
    GetExitCodeProcess(pi.hProcess, &dwExitCode);
    HookTrace("InjectHookDllCrossArch helper exitCode=%lu helper=%ls crossDll=%ls",
              dwExitCode, szHelper, szCrossDll);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Restore handle to non-inheritable
    SetHandleInformation(hProcess, HANDLE_FLAG_INHERIT, 0);

    return dwExitCode;
}

static DWORD InjectHookDllForChild(HANDLE hProcess, const char* traceContext) {
    if (!hProcess)
        return ERROR_INVALID_HANDLE;

    DWORD injectStatus = ERROR_SUCCESS;
    if (IsChildSameArchitecture(hProcess)) {
        HookTrace("%s same-arch inject process=%p", traceContext, hProcess);
        injectStatus = InjectHookDll(hProcess, g_szHookDllPath);
    } else {
        HookTrace("%s cross-arch inject process=%p", traceContext, hProcess);
        injectStatus = InjectHookDllCrossArch(hProcess);
    }

    HookTrace("%s inject status=%lu", traceContext, injectStatus);
    return injectStatus;
}

// ============================================================================
// Hooked Functions — File Operations
// ============================================================================

static NTSTATUS NTAPI Hook_NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
    PVOID EaBuffer, ULONG EaLength)
{
    // Avoid recursion from broker pipe operations
    if (g_bInBrokerCall)
        return Original_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);

    WCHAR szNtPath[MAX_PATH];
    if (!OaToNtPath(ObjectAttributes, szNtPath, MAX_PATH, TRUE))
        return Original_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);

    // Device paths (\Device\CNG, \Device\KsecDD, etc.) can't be brokered.
    if (!IsBrokerablePath(szNtPath))
        return Original_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);

    // Note: EaBuffer/EaLength (extended attributes) are not forwarded to the
    // broker.  EAs are rarely used by normal Win32 applications and cannot be
    // easily serialized over the pipe protocol.  If the caller specified EAs,
    // the brokered file will be created without them.
    HANDLE hBrokered = INVALID_HANDLE_VALUE;
    ULONG_PTR information = FILE_OPENED;
    NTSTATUS brokerStatus = g_client.OpenFile(
        szNtPath, DesiredAccess,
        AllocationSize ? AllocationSize->QuadPart : 0LL,
        FileAttributes, ShareAccess, CreateDisposition, CreateOptions,
        ObjectAttributes->Attributes,
        &hBrokered, &information);

    if (!NT_SUCCESS(brokerStatus))
        return brokerStatus;

    *FileHandle = hBrokered;
    IoStatusBlock->Status = STATUS_SUCCESS;
    IoStatusBlock->Information = information;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI Hook_NtOpenFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions)
{
    // Avoid recursion from broker pipe operations
    if (g_bInBrokerCall)
        return Original_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, ShareAccess, OpenOptions);
    
    WCHAR szNtPath[MAX_PATH];
    if (!OaToNtPath(ObjectAttributes, szNtPath, MAX_PATH, TRUE))
        return Original_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, ShareAccess, OpenOptions);

    // Device paths (\Device\CNG, \Device\KsecDD, etc.) can't be brokered.
    if (!IsBrokerablePath(szNtPath))
        return Original_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, ShareAccess, OpenOptions);

    HANDLE hBrokered = INVALID_HANDLE_VALUE;
    ULONG_PTR information = FILE_OPENED;
    // NtOpenFile is always FILE_OPEN disposition; OpenOptions maps to CreateOptions
    NTSTATUS brokerStatus = g_client.OpenFile(
        szNtPath, DesiredAccess,
        0LL, 0,
        ShareAccess, FILE_OPEN, OpenOptions,
        ObjectAttributes->Attributes,
        &hBrokered, &information);

    if (!NT_SUCCESS(brokerStatus))
        return brokerStatus;

    *FileHandle = hBrokered;
    IoStatusBlock->Status = STATUS_SUCCESS;
    IoStatusBlock->Information = information;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI Hook_NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes) {
    // Avoid recursion from broker pipe operations
    if (g_bInBrokerCall)
        return Original_NtDeleteFile(ObjectAttributes);

    NTSTATUS status = Original_NtDeleteFile(ObjectAttributes);

    if (status != STATUS_ACCESS_DENIED)
        return status;

    WCHAR szNtPath[MAX_PATH];
    if (!OaToNtPath(ObjectAttributes, szNtPath, MAX_PATH, TRUE))
        return status;

    NTSTATUS brokerStatus = g_client.DeleteFile(szNtPath, ObjectAttributes->Attributes);
    return NT_SUCCESS(brokerStatus) ? STATUS_SUCCESS : brokerStatus;
}

static NTSTATUS NTAPI Hook_NtQueryAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes, PVOID FileInformation)
{
    // Avoid recursion from broker pipe operations
    if (g_bInBrokerCall)
        return Original_NtQueryAttributesFile(ObjectAttributes, FileInformation);

    NTSTATUS status = Original_NtQueryAttributesFile(ObjectAttributes, FileInformation);

    if (status != STATUS_ACCESS_DENIED)
        return status;

    WCHAR szNtPath[MAX_PATH];
    if (!OaToNtPath(ObjectAttributes, szNtPath, MAX_PATH, TRUE))
        return status;

    BrokerFileInfo info = {};
    NTSTATUS brokerStatus = g_client.QueryFile(szNtPath, ObjectAttributes->Attributes, &info);

    if (!NT_SUCCESS(brokerStatus))
        return brokerStatus;

    // NtQueryAttributesFile output is FILE_BASIC_INFORMATION:
    // CreationTime, LastAccessTime, LastWriteTime, ChangeTime (LARGE_INTEGER x4),
    // FileAttributes (ULONG)
    auto* pBasicInfo = reinterpret_cast<FILE_BASIC_INFO*>(FileInformation);
    ZeroMemory(pBasicInfo, sizeof(FILE_BASIC_INFO));
    pBasicInfo->CreationTime.QuadPart   = info.CreationTime;
    pBasicInfo->LastAccessTime.QuadPart = info.LastAccessTime;
    pBasicInfo->LastWriteTime.QuadPart  = info.LastWriteTime;
    pBasicInfo->ChangeTime.QuadPart     = info.ChangeTime;
    pBasicInfo->FileAttributes          = info.FileAttributes;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI Hook_NtQueryFullAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes, PVOID FileInformation)
{
    // Avoid recursion from broker pipe operations
    if (g_bInBrokerCall)
        return Original_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);

    NTSTATUS status = Original_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);

    if (status != STATUS_ACCESS_DENIED)
        return status;

    WCHAR szNtPath[MAX_PATH];
    if (!OaToNtPath(ObjectAttributes, szNtPath, MAX_PATH, TRUE))
        return status;

    BrokerFileInfo info = {};
    NTSTATUS brokerStatus = g_client.QueryFile(szNtPath, ObjectAttributes->Attributes, &info);

    if (!NT_SUCCESS(brokerStatus))
        return brokerStatus;

    auto* pNetInfo = reinterpret_cast<FILE_NETWORK_OPEN_INFORMATION*>(FileInformation);
    ZeroMemory(pNetInfo, sizeof(FILE_NETWORK_OPEN_INFORMATION));
    pNetInfo->CreationTime.QuadPart   = info.CreationTime;
    pNetInfo->LastAccessTime.QuadPart = info.LastAccessTime;
    pNetInfo->LastWriteTime.QuadPart  = info.LastWriteTime;
    pNetInfo->ChangeTime.QuadPart     = info.ChangeTime;
    pNetInfo->AllocationSize.QuadPart = info.AllocationSize;
    pNetInfo->EndOfFile.QuadPart      = info.EndOfFile;
    pNetInfo->FileAttributes          = info.FileAttributes;
    return STATUS_SUCCESS;
}

// ============================================================================
// Hooked Functions — Registry Operations
// ============================================================================

static NTSTATUS NTAPI Hook_NtOpenKey(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes)
{
    // Avoid recursion from broker pipe operations
    if (g_bInBrokerCall)
        return Original_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);

    NTSTATUS status = Original_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);

    if (status != STATUS_ACCESS_DENIED)
        return status;

    WCHAR szNtPath[MAX_PATH];
    if (!OaToNtPath(ObjectAttributes, szNtPath, MAX_PATH, FALSE))
        return status;

    HANDLE hBrokered = nullptr;
    NTSTATUS brokerStatus = g_client.OpenRegKey(szNtPath, ObjectAttributes->Attributes,
                                              DesiredAccess, 0, &hBrokered);

    if (!NT_SUCCESS(brokerStatus))
        return brokerStatus;

    *KeyHandle = hBrokered;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI Hook_NtOpenKeyEx(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions)
{
    // Avoid recursion from broker pipe operations
    if (g_bInBrokerCall)
        return Original_NtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);

    NTSTATUS status = Original_NtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);

    if (status != STATUS_ACCESS_DENIED)
        return status;

    WCHAR szNtPath[MAX_PATH];
    if (!OaToNtPath(ObjectAttributes, szNtPath, MAX_PATH, FALSE))
        return status;

    HANDLE hBrokered = nullptr;
    NTSTATUS brokerStatus = g_client.OpenRegKey(szNtPath, ObjectAttributes->Attributes,
                                              DesiredAccess, OpenOptions, &hBrokered);

    if (!NT_SUCCESS(brokerStatus))
        return brokerStatus;

    *KeyHandle = hBrokered;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI Hook_NtCreateKey(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
    PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition)
{
    // Avoid recursion from broker pipe operations
    if (g_bInBrokerCall)
        return Original_NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
            TitleIndex, Class, CreateOptions, Disposition);

    NTSTATUS status = Original_NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
        TitleIndex, Class, CreateOptions, Disposition);

    if (status != STATUS_ACCESS_DENIED)
        return status;

    WCHAR szNtPath[MAX_PATH];
    if (!OaToNtPath(ObjectAttributes, szNtPath, MAX_PATH, FALSE))
        return status;

    // Extract Class string (usually NULL)
    LPCWSTR szClass = nullptr;
    WCHAR szClassBuf[256] = {};
    if (Class && Class->Buffer && Class->Length > 0) {
        USHORT nChars = Class->Length / sizeof(WCHAR);
        if (nChars < _countof(szClassBuf)) {
            memcpy(szClassBuf, Class->Buffer, nChars * sizeof(WCHAR));
            szClassBuf[nChars] = L'\0';
            szClass = szClassBuf;
        }
    }

    HANDLE hBrokered = nullptr;
    ULONG disposition = 0;
    NTSTATUS brokerStatus = g_client.CreateRegKey(szNtPath, ObjectAttributes->Attributes,
                                                DesiredAccess, TitleIndex,
                                                szClass, CreateOptions,
                                                &hBrokered, &disposition);

    if (!NT_SUCCESS(brokerStatus))
        return brokerStatus;

    *KeyHandle = hBrokered;
    if (Disposition) *Disposition = disposition;
    return STATUS_SUCCESS;
}

// NtQueryValueKey and NtSetValueKey operate on already-opened handles.
// If the handle was obtained through the broker, these calls succeed without
// further brokering.

static NTSTATUS NTAPI Hook_NtQueryValueKey(
    HANDLE KeyHandle, PUNICODE_STRING ValueName,
    ULONG KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG Length, PULONG ResultLength)
{
    return Original_NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass,
        KeyValueInformation, Length, ResultLength);
}

static NTSTATUS NTAPI Hook_NtSetValueKey(
    HANDLE KeyHandle, PUNICODE_STRING ValueName,
    ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)
{
    return Original_NtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}

static NTSTATUS NTAPI Hook_NtDeleteKey(HANDLE KeyHandle) {
    return Original_NtDeleteKey(KeyHandle);
}

// ============================================================================
// Hooked Functions — Process Operations
// ============================================================================

static NTSTATUS NTAPI Hook_NtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PVOID ClientId)
{
    // Avoid recursion from broker pipe operations
    if (g_bInBrokerCall)
        return Original_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    NTSTATUS status = Original_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    if (status != STATUS_ACCESS_DENIED)
        return status;

    // CLIENT_ID: first field is UniqueProcess (a HANDLE-width PID)
    DWORD dwTargetPid = (DWORD)(ULONG_PTR)(((HANDLE*)ClientId)[0]);

    HANDLE hBrokered = nullptr;
    NTSTATUS brokerStatus = g_client.OpenProcess(DesiredAccess, dwTargetPid, &hBrokered);

    if (!NT_SUCCESS(brokerStatus))
        return brokerStatus;

    *ProcessHandle = hBrokered;
    return STATUS_SUCCESS;
}

// ============================================================================
// Hooked Functions — Subprocess Propagation
// ============================================================================

static NTSTATUS NTAPI Hook_NtCreateUserProcess(
    PHANDLE ProcessHandle, PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags, ULONG ThreadFlags,
    PVOID ProcessParameters, PVOID CreateInfo, PVOID AttributeList)
{
    HookTrace("NtCreateUserProcess enter processFlags=0x%08lX threadFlags=0x%08lX spawningHelper=%d",
              ProcessFlags, ThreadFlags, g_bSpawningHelper ? 1 : 0);

    // Pass through when spawning the cross-arch injection helper
    if (g_bSpawningHelper) {
        NTSTATUS helperStatus = Original_NtCreateUserProcess(
            ProcessHandle, ThreadHandle,
            ProcessDesiredAccess, ThreadDesiredAccess,
            ProcessObjectAttributes, ThreadObjectAttributes,
            ProcessFlags, ThreadFlags,
            ProcessParameters, CreateInfo, AttributeList);
        HookTrace("NtCreateUserProcess helper passthrough status=0x%08lX", helperStatus);
        return helperStatus;
    }

    BOOL bWasSuspended = (ThreadFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED);

    NTSTATUS status = Original_NtCreateUserProcess(
        ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        ProcessFlags, ThreadFlags,
        ProcessParameters, CreateInfo, AttributeList);

    HookTrace("NtCreateUserProcess original returned status=0x%08lX process=%p thread=%p",
              status, ProcessHandle ? *ProcessHandle : nullptr, ThreadHandle ? *ThreadHandle : nullptr);

    if (status != STATUS_SUCCESS)
        return status;

    BOOL pendingAdded = FALSE;
    if (bWasSuspended && ProcessHandle && ThreadHandle && *ProcessHandle && *ThreadHandle)
        pendingAdded = AddPendingChild(*ProcessHandle, *ThreadHandle) ? TRUE : FALSE;

    HookTrace("NtCreateUserProcess pending child added=%d process=%p thread=%p wasSuspended=%d",
              pendingAdded ? 1 : 0,
              ProcessHandle ? *ProcessHandle : nullptr,
              ThreadHandle ? *ThreadHandle : nullptr,
              bWasSuspended ? 1 : 0);

    if (!pendingAdded && ProcessHandle && *ProcessHandle) {
        InjectHookDllForChild(*ProcessHandle, "NtCreateUserProcess fallback");

        if (!bWasSuspended && Original_NtResumeThread && ThreadHandle && *ThreadHandle) {
            HookTrace("NtCreateUserProcess fallback resume thread=%p", *ThreadHandle);
            Original_NtResumeThread(*ThreadHandle, nullptr);
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI Hook_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    HANDLE hPendingProcess = TakePendingChildByThread(ThreadHandle);
    // HookTrace("NtResumeThread enter thread=%p pendingProcess=%p", ThreadHandle, hPendingProcess);

    if (hPendingProcess)
        InjectHookDllForChild(hPendingProcess, "NtResumeThread");

    NTSTATUS status = Original_NtResumeThread(ThreadHandle, PreviousSuspendCount);
    // HookTrace("NtResumeThread exit status=0x%08lX", status);
    return status;
}

// ============================================================================
// Inline Hooking Engine
// ============================================================================

PVOID InstallInlineHook(PVOID pTarget, PVOID pDetour, BYTE* pSavedBytes, DWORD* pdwPatchSize) {
    if (!pTarget || !pDetour)
        return nullptr;

#ifdef _WIN64
    // x64 ntdll Nt* exports are syscall stubs with a short conditional branch
    // and syscall/int 0x2e fallback sequence. Copy the full 24-byte stub so the
    // trampoline preserves whole instructions and keeps the relative branch
    // target within the copied block.
    const DWORD dwPatchSize = 24;
#else
    // x86: 5-byte relative jump: E9 <rel32>
    const DWORD dwPatchSize = 5;
#endif

    *pdwPatchSize = dwPatchSize;

    // Save original bytes
    memcpy(pSavedBytes, pTarget, dwPatchSize);

    // Allocate trampoline: original bytes + jump back
    DWORD dwTrampolineSize = dwPatchSize + 14; // Max jump size
    PVOID pTrampoline = VirtualAlloc(nullptr, dwTrampolineSize,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    if (!pTrampoline)
        return nullptr;

    // Copy original bytes to trampoline
    memcpy(pTrampoline, pSavedBytes, dwPatchSize);

    // Write jump-back from trampoline to original+N
    BYTE* pTrampolineJump = (BYTE*)pTrampoline + dwPatchSize;
    BYTE* pOriginalContinue = (BYTE*)pTarget + dwPatchSize;

#ifdef _WIN64
    // JMP [RIP+0] followed by 8-byte address
    pTrampolineJump[0] = 0xFF;
    pTrampolineJump[1] = 0x25;
    *(DWORD*)(pTrampolineJump + 2) = 0; // RIP-relative offset = 0
    *(UINT64*)(pTrampolineJump + 6) = (UINT64)pOriginalContinue;
#else
    pTrampolineJump[0] = 0xE9;
    *(DWORD*)(pTrampolineJump + 1) = (DWORD)((BYTE*)pOriginalContinue - (pTrampolineJump + 5));
#endif

    // Now overwrite the target function with a jump to our detour
    DWORD dwOldProtect;
    VirtualProtect(pTarget, dwPatchSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

#ifdef _WIN64
    // MOV RAX, <detour address>; JMP RAX
    BYTE* p = (BYTE*)pTarget;
    p[0] = 0x48; p[1] = 0xB8;
    *(UINT64*)(p + 2) = (UINT64)pDetour;
    p[10] = 0xFF; p[11] = 0xE0;
#else
    BYTE* p = (BYTE*)pTarget;
    p[0] = 0xE9;
    *(DWORD*)(p + 1) = (DWORD)((BYTE*)pDetour - (p + 5));
#endif

    VirtualProtect(pTarget, dwPatchSize, dwOldProtect, &dwOldProtect);
    FlushInstructionCache(GetCurrentProcess(), pTarget, dwPatchSize);

    return pTrampoline;
}

void RemoveInlineHook(PVOID pTarget, const BYTE* pSavedBytes, DWORD dwPatchSize) {
    DWORD dwOldProtect;
    VirtualProtect(pTarget, dwPatchSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    memcpy(pTarget, pSavedBytes, dwPatchSize);
    VirtualProtect(pTarget, dwPatchSize, dwOldProtect, &dwOldProtect);
    FlushInstructionCache(GetCurrentProcess(), pTarget, dwPatchSize);
}

// ============================================================================
// Hook Installation Helper
// ============================================================================

static BOOL InstallHook(const char* szName, PVOID pDetour, PVOID* ppOriginal) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return FALSE;

    PVOID pTarget = (PVOID)GetProcAddress(hNtdll, szName);
    if (!pTarget)
        return FALSE;

    HookEntry& entry = g_hooks[g_hookCount];
    entry.szFunctionName = szName;
    entry.pOriginalFunc  = pTarget;
    entry.pDetourFunc    = pDetour;

    entry.pTrampoline = InstallInlineHook(pTarget, pDetour, entry.originalBytes, &entry.dwPatchSize);
    if (!entry.pTrampoline)
        return FALSE;

    *ppOriginal = entry.pTrampoline;
    g_hookCount++;
    return TRUE;
}

// ============================================================================
// Broker Client Implementation
// ============================================================================

HookBrokerClient::HookBrokerClient()
    : m_hPipe(INVALID_HANDLE_VALUE)
    , m_dwNextRequestId(1)
{
    InitializeCriticalSection(&m_cs);
}

HookBrokerClient::~HookBrokerClient() {
    Disconnect();
    DeleteCriticalSection(&m_cs);
}

DWORD HookBrokerClient::Connect() {
    WCHAR szPipeName[128];
    DWORD dwLen = GetEnvironmentVariable(BROKER_PIPE_ENV_VAR, szPipeName, _countof(szPipeName));
    if (dwLen == 0)
        return GetLastError();

    // Wait for the pipe to become available
    if (!WaitNamedPipe(szPipeName, 5000))
        return GetLastError();

    m_hPipe = CreateFile(szPipeName,
                         GENERIC_READ | GENERIC_WRITE,
                         0, nullptr,
                         OPEN_EXISTING,
                         0, nullptr);

    if (m_hPipe == INVALID_HANDLE_VALUE)
        return GetLastError();

    DWORD dwMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(m_hPipe, &dwMode, nullptr, nullptr)) {
        DWORD err = GetLastError();
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
        return err;
    }

    return ERROR_SUCCESS;
}

void HookBrokerClient::Disconnect() {
    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }
}

DWORD HookBrokerClient::Transact(const BYTE* pRequest, DWORD dwRequestSize,
                                  BYTE* pResponse, DWORD dwResponseBufSize,
                                  DWORD& dwResponseSize) {
    if (m_hPipe == INVALID_HANDLE_VALUE)
        return ERROR_PIPE_NOT_CONNECTED;

    EnterCriticalSection(&m_cs);
    g_bInBrokerCall = TRUE;

    DWORD dwBytesWritten = 0;
    if (!WriteFile(m_hPipe, pRequest, dwRequestSize, &dwBytesWritten, nullptr)) {
        g_bInBrokerCall = FALSE;
        LeaveCriticalSection(&m_cs);
        return GetLastError();
    }

    DWORD dwTotalRead = 0;
    BOOL bSuccess;
    do {
        DWORD dwBytesRead = 0;
        bSuccess = ReadFile(m_hPipe, pResponse + dwTotalRead,
                            dwResponseBufSize - dwTotalRead, &dwBytesRead, nullptr);
        dwTotalRead += dwBytesRead;

        if (!bSuccess && GetLastError() != ERROR_MORE_DATA) {
            g_bInBrokerCall = FALSE;
            LeaveCriticalSection(&m_cs);
            return GetLastError();
        }
    } while (!bSuccess);

    g_bInBrokerCall = FALSE;
    LeaveCriticalSection(&m_cs);
    dwResponseSize = dwTotalRead;
    return ERROR_SUCCESS;
}

DWORD HookBrokerClient::Ping() {
    BYTE requestBuf[sizeof(BrokerMessageHeader)];
    auto* pHeader = reinterpret_cast<BrokerMessageHeader*>(requestBuf);
    pHeader->dwTotalSize = sizeof(BrokerMessageHeader);
    pHeader->dwRequestId = m_dwNextRequestId++;
    pHeader->dwOperation = BROKER_OP_PING;
    pHeader->dwProcessId = GetCurrentProcessId();

    BYTE responseBuf[sizeof(BrokerResponseHeader)];
    DWORD dwResponseSize = 0;
    DWORD fStatus = Transact(requestBuf, sizeof(requestBuf), responseBuf, sizeof(responseBuf), dwResponseSize);
    if (fStatus != ERROR_SUCCESS) return fStatus;

    return reinterpret_cast<BrokerResponseHeader*>(responseBuf)->dwStatus;
}

DWORD HookBrokerClient::Trace(const char* szMessage) {
    if (!szMessage)
        return ERROR_INVALID_PARAMETER;

    DWORD dwMessageBytes = static_cast<DWORD>(strlen(szMessage) + 1);
    DWORD dwPayloadSize  = offsetof(TraceRequestPayload, szMessage) + dwMessageBytes;
    DWORD dwRequestSize  = sizeof(BrokerMessageHeader) + dwPayloadSize;

    BYTE requestBuf[BROKER_MAX_MESSAGE_SIZE];
    auto* pHeader = reinterpret_cast<BrokerMessageHeader*>(requestBuf);
    pHeader->dwTotalSize = dwRequestSize;
    pHeader->dwRequestId = m_dwNextRequestId++;
    pHeader->dwOperation = BROKER_OP_TRACE;
    pHeader->dwProcessId = GetCurrentProcessId();

    auto* pPayload = reinterpret_cast<TraceRequestPayload*>(requestBuf + sizeof(BrokerMessageHeader));
    pPayload->dwMessageLengthBytes = dwMessageBytes;
    memcpy(pPayload->szMessage, szMessage, dwMessageBytes);

    BYTE responseBuf[sizeof(BrokerResponseHeader)];
    DWORD dwResponseSize = 0;
    DWORD fStatus = Transact(requestBuf, dwRequestSize, responseBuf, sizeof(responseBuf), dwResponseSize);
    if (fStatus != ERROR_SUCCESS) return fStatus;

    return reinterpret_cast<BrokerResponseHeader*>(responseBuf)->dwStatus;
}

NTSTATUS HookBrokerClient::OpenFile(LPCWSTR szNtPath, ACCESS_MASK DesiredAccess,
                                  LONGLONG AllocationSize, ULONG FileAttributes,
                                  ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                                  ULONG ObjAttributes,
                                  HANDLE* phHandle, ULONG_PTR* pInformation) {
    DWORD dwPathBytes   = (lstrlenW(szNtPath) + 1) * sizeof(WCHAR);
    DWORD dwPayloadSize = offsetof(OpenFileRequestPayload, szNtPath) + dwPathBytes;
    DWORD dwRequestSize = sizeof(BrokerMessageHeader) + dwPayloadSize;

    BYTE requestBuf[BROKER_MAX_MESSAGE_SIZE];
    auto* pHeader = reinterpret_cast<BrokerMessageHeader*>(requestBuf);
    pHeader->dwTotalSize = dwRequestSize;
    pHeader->dwRequestId = m_dwNextRequestId++;
    pHeader->dwOperation = BROKER_OP_OPEN_FILE;
    pHeader->dwProcessId = GetCurrentProcessId();

    auto* pPayload = reinterpret_cast<OpenFileRequestPayload*>(requestBuf + sizeof(BrokerMessageHeader));
    pPayload->DesiredAccess     = DesiredAccess;
    pPayload->AllocationSize    = AllocationSize;
    pPayload->FileAttributes    = FileAttributes;
    pPayload->ShareAccess       = ShareAccess;
    pPayload->CreateDisposition = CreateDisposition;
    pPayload->CreateOptions     = CreateOptions;
    pPayload->ObjAttributes     = ObjAttributes;
    pPayload->dwPathLengthBytes = dwPathBytes;
    memcpy(pPayload->szNtPath, szNtPath, dwPathBytes);

    BYTE responseBuf[BROKER_MAX_MESSAGE_SIZE];
    DWORD dwResponseSize = 0;
    DWORD fStatus = Transact(requestBuf, dwRequestSize, responseBuf, sizeof(responseBuf), dwResponseSize);
    if (fStatus != ERROR_SUCCESS) return (NTSTATUS)STATUS_UNSUCCESSFUL;

    auto* pResp = reinterpret_cast<BrokerResponseHeader*>(responseBuf);
    if (NT_SUCCESS((NTSTATUS)pResp->dwStatus)) {
        *phHandle = (HANDLE)pResp->dwHandle;
        if (pInformation &&
            dwResponseSize >= sizeof(BrokerResponseHeader) + sizeof(OpenFileResponsePayload)) {
            auto* pRespPayload = reinterpret_cast<OpenFileResponsePayload*>(
                responseBuf + sizeof(BrokerResponseHeader));
            *pInformation = (ULONG_PTR)pRespPayload->Information;
        }
    }
    return (NTSTATUS)pResp->dwStatus;
}

NTSTATUS HookBrokerClient::DeleteFile(LPCWSTR szNtPath, ULONG ObjAttributes) {
    DWORD dwPathBytes   = (lstrlenW(szNtPath) + 1) * sizeof(WCHAR);
    DWORD dwPayloadSize = offsetof(DeleteFileRequestPayload, szNtPath) + dwPathBytes;
    DWORD dwRequestSize = sizeof(BrokerMessageHeader) + dwPayloadSize;

    BYTE requestBuf[BROKER_MAX_MESSAGE_SIZE];
    auto* pHeader = reinterpret_cast<BrokerMessageHeader*>(requestBuf);
    pHeader->dwTotalSize = dwRequestSize;
    pHeader->dwRequestId = m_dwNextRequestId++;
    pHeader->dwOperation = BROKER_OP_DELETE_FILE;
    pHeader->dwProcessId = GetCurrentProcessId();

    auto* pPayload = reinterpret_cast<DeleteFileRequestPayload*>(requestBuf + sizeof(BrokerMessageHeader));
    pPayload->ObjAttributes     = ObjAttributes;
    pPayload->dwPathLengthBytes = dwPathBytes;
    memcpy(pPayload->szNtPath, szNtPath, dwPathBytes);

    BYTE responseBuf[sizeof(BrokerResponseHeader)];
    DWORD dwResponseSize = 0;
    DWORD fStatus = Transact(requestBuf, dwRequestSize, responseBuf, sizeof(responseBuf), dwResponseSize);
    if (fStatus != ERROR_SUCCESS) return (NTSTATUS)STATUS_UNSUCCESSFUL;

    return (NTSTATUS)reinterpret_cast<BrokerResponseHeader*>(responseBuf)->dwStatus;
}

NTSTATUS HookBrokerClient::QueryFile(LPCWSTR szNtPath, ULONG ObjAttributes, BrokerFileInfo* pInfo) {
    DWORD dwPathBytes   = (lstrlenW(szNtPath) + 1) * sizeof(WCHAR);
    DWORD dwPayloadSize = offsetof(QueryFileRequestPayload, szNtPath) + dwPathBytes;
    DWORD dwRequestSize = sizeof(BrokerMessageHeader) + dwPayloadSize;

    BYTE requestBuf[BROKER_MAX_MESSAGE_SIZE];
    auto* pHeader = reinterpret_cast<BrokerMessageHeader*>(requestBuf);
    pHeader->dwTotalSize = dwRequestSize;
    pHeader->dwRequestId = m_dwNextRequestId++;
    pHeader->dwOperation = BROKER_OP_QUERY_FILE;
    pHeader->dwProcessId = GetCurrentProcessId();

    auto* pPayload = reinterpret_cast<QueryFileRequestPayload*>(requestBuf + sizeof(BrokerMessageHeader));
    pPayload->ObjAttributes     = ObjAttributes;
    pPayload->dwPathLengthBytes = dwPathBytes;
    memcpy(pPayload->szNtPath, szNtPath, dwPathBytes);

    BYTE responseBuf[BROKER_MAX_MESSAGE_SIZE];
    DWORD dwResponseSize = 0;
    DWORD fStatus = Transact(requestBuf, dwRequestSize, responseBuf, sizeof(responseBuf), dwResponseSize);
    if (fStatus != ERROR_SUCCESS) return (NTSTATUS)STATUS_UNSUCCESSFUL;

    auto* pResp = reinterpret_cast<BrokerResponseHeader*>(responseBuf);
    if (NT_SUCCESS((NTSTATUS)pResp->dwStatus) && pInfo &&
        dwResponseSize >= sizeof(BrokerResponseHeader) + sizeof(QueryFileResponsePayload)) {
        auto* p = reinterpret_cast<QueryFileResponsePayload*>(responseBuf + sizeof(BrokerResponseHeader));
        pInfo->CreationTime   = p->CreationTime;
        pInfo->LastAccessTime = p->LastAccessTime;
        pInfo->LastWriteTime  = p->LastWriteTime;
        pInfo->ChangeTime     = p->ChangeTime;
        pInfo->AllocationSize = p->AllocationSize;
        pInfo->EndOfFile      = p->EndOfFile;
        pInfo->FileAttributes = p->FileAttributes;
    }
    return (NTSTATUS)pResp->dwStatus;
}

NTSTATUS HookBrokerClient::OpenRegKey(LPCWSTR szNtPath, ULONG ObjAttributes,
                                    ACCESS_MASK DesiredAccess, ULONG OpenOptions, HANDLE* phHandle) {
    DWORD dwPathBytes   = (lstrlenW(szNtPath) + 1) * sizeof(WCHAR);
    DWORD dwPayloadSize = offsetof(OpenRegRequestPayload, szNtPath) + dwPathBytes;
    DWORD dwRequestSize = sizeof(BrokerMessageHeader) + dwPayloadSize;

    BYTE requestBuf[BROKER_MAX_MESSAGE_SIZE];
    auto* pHeader = reinterpret_cast<BrokerMessageHeader*>(requestBuf);
    pHeader->dwTotalSize = dwRequestSize;
    pHeader->dwRequestId = m_dwNextRequestId++;
    pHeader->dwOperation = BROKER_OP_OPEN_REG;
    pHeader->dwProcessId = GetCurrentProcessId();

    auto* pPayload = reinterpret_cast<OpenRegRequestPayload*>(requestBuf + sizeof(BrokerMessageHeader));
    pPayload->DesiredAccess     = DesiredAccess;
    pPayload->ObjAttributes     = ObjAttributes;
    pPayload->OpenOptions       = OpenOptions;
    pPayload->dwPathLengthBytes = dwPathBytes;
    memcpy(pPayload->szNtPath, szNtPath, dwPathBytes);

    BYTE responseBuf[sizeof(BrokerResponseHeader)];
    DWORD dwResponseSize = 0;
    DWORD fStatus = Transact(requestBuf, dwRequestSize, responseBuf, sizeof(responseBuf), dwResponseSize);
    if (fStatus != ERROR_SUCCESS) return (NTSTATUS)STATUS_UNSUCCESSFUL;

    auto* pResp = reinterpret_cast<BrokerResponseHeader*>(responseBuf);
    if (NT_SUCCESS((NTSTATUS)pResp->dwStatus))
        *phHandle = (HANDLE)pResp->dwHandle;
    return (NTSTATUS)pResp->dwStatus;
}

NTSTATUS HookBrokerClient::QueryRegValue(LPCWSTR szNtPath, ULONG ObjAttributes, LPCWSTR szValueName,
                                       DWORD* pdwType, BYTE* pData, DWORD dwBufSize, DWORD* pdwDataSize) {
    DWORD dwPathBytes      = (lstrlenW(szNtPath) + 1) * sizeof(WCHAR);
    DWORD dwValueNameBytes = (lstrlenW(szValueName) + 1) * sizeof(WCHAR);
    DWORD dwPayloadSize    = offsetof(QueryRegRequestPayload, szData) + dwPathBytes + dwValueNameBytes;
    DWORD dwRequestSize    = sizeof(BrokerMessageHeader) + dwPayloadSize;

    BYTE requestBuf[BROKER_MAX_MESSAGE_SIZE];
    auto* pHeader = reinterpret_cast<BrokerMessageHeader*>(requestBuf);
    pHeader->dwTotalSize = dwRequestSize;
    pHeader->dwRequestId = m_dwNextRequestId++;
    pHeader->dwOperation = BROKER_OP_QUERY_REG;
    pHeader->dwProcessId = GetCurrentProcessId();

    auto* pPayload = reinterpret_cast<QueryRegRequestPayload*>(requestBuf + sizeof(BrokerMessageHeader));
    pPayload->ObjAttributes          = ObjAttributes;
    pPayload->dwPathLengthBytes      = dwPathBytes;
    pPayload->dwValueNameLengthBytes = dwValueNameBytes;
    memcpy(pPayload->szData, szNtPath, dwPathBytes);
    memcpy((BYTE*)pPayload->szData + dwPathBytes, szValueName, dwValueNameBytes);

    BYTE responseBuf[BROKER_MAX_MESSAGE_SIZE];
    DWORD dwResponseSize = 0;
    DWORD fStatus = Transact(requestBuf, dwRequestSize, responseBuf, sizeof(responseBuf), dwResponseSize);
    if (fStatus != ERROR_SUCCESS) return (NTSTATUS)STATUS_UNSUCCESSFUL;

    auto* pResp = reinterpret_cast<BrokerResponseHeader*>(responseBuf);
    if (NT_SUCCESS((NTSTATUS)pResp->dwStatus)) {
        auto* p = reinterpret_cast<QueryRegResponsePayload*>(responseBuf + sizeof(BrokerResponseHeader));
        if (pdwType)     *pdwType     = p->dwRegType;
        if (pdwDataSize) *pdwDataSize = p->dwDataSize;
        if (pData && dwBufSize >= p->dwDataSize)
            memcpy(pData, p->data, p->dwDataSize);
    }
    return (NTSTATUS)pResp->dwStatus;
}

NTSTATUS HookBrokerClient::WriteRegValue(LPCWSTR szNtPath, ULONG ObjAttributes, LPCWSTR szValueName,
                                       DWORD dwType, const BYTE* pData, DWORD dwDataSize) {
    DWORD dwPathBytes      = (lstrlenW(szNtPath) + 1) * sizeof(WCHAR);
    DWORD dwValueNameBytes = (lstrlenW(szValueName) + 1) * sizeof(WCHAR);
    DWORD dwPayloadSize    = offsetof(WriteRegRequestPayload, szData) + dwPathBytes + dwValueNameBytes + dwDataSize;
    DWORD dwRequestSize    = sizeof(BrokerMessageHeader) + dwPayloadSize;

    BYTE requestBuf[BROKER_MAX_MESSAGE_SIZE];
    auto* pHeader = reinterpret_cast<BrokerMessageHeader*>(requestBuf);
    pHeader->dwTotalSize = dwRequestSize;
    pHeader->dwRequestId = m_dwNextRequestId++;
    pHeader->dwOperation = BROKER_OP_WRITE_REG;
    pHeader->dwProcessId = GetCurrentProcessId();

    auto* pPayload = reinterpret_cast<WriteRegRequestPayload*>(requestBuf + sizeof(BrokerMessageHeader));
    pPayload->ObjAttributes          = ObjAttributes;
    pPayload->dwRegType              = dwType;
    pPayload->dwPathLengthBytes      = dwPathBytes;
    pPayload->dwValueNameLengthBytes = dwValueNameBytes;
    pPayload->dwDataSize             = dwDataSize;
    BYTE* pDest = (BYTE*)pPayload->szData;
    memcpy(pDest, szNtPath,    dwPathBytes);      pDest += dwPathBytes;
    memcpy(pDest, szValueName, dwValueNameBytes); pDest += dwValueNameBytes;
    memcpy(pDest, pData,       dwDataSize);

    BYTE responseBuf[sizeof(BrokerResponseHeader)];
    DWORD dwResponseSize = 0;
    DWORD fStatus = Transact(requestBuf, dwRequestSize, responseBuf, sizeof(responseBuf), dwResponseSize);
    if (fStatus != ERROR_SUCCESS) return (NTSTATUS)STATUS_UNSUCCESSFUL;

    return (NTSTATUS)reinterpret_cast<BrokerResponseHeader*>(responseBuf)->dwStatus;
}

NTSTATUS HookBrokerClient::CreateRegKey(LPCWSTR szNtPath, ULONG ObjAttributes,
                                      ACCESS_MASK DesiredAccess, ULONG TitleIndex,
                                      LPCWSTR szClass, ULONG CreateOptions,
                                      HANDLE* phHandle, ULONG* pDisposition) {
    DWORD dwPathBytes  = (lstrlenW(szNtPath) + 1) * sizeof(WCHAR);
    DWORD dwClassBytes = szClass ? (lstrlenW(szClass) + 1) * sizeof(WCHAR) : 0;
    DWORD dwPayloadSize = offsetof(CreateRegRequestPayload, szData) + dwPathBytes + dwClassBytes;
    DWORD dwRequestSize = sizeof(BrokerMessageHeader) + dwPayloadSize;

    BYTE requestBuf[BROKER_MAX_MESSAGE_SIZE];
    auto* pHeader = reinterpret_cast<BrokerMessageHeader*>(requestBuf);
    pHeader->dwTotalSize = dwRequestSize;
    pHeader->dwRequestId = m_dwNextRequestId++;
    pHeader->dwOperation = BROKER_OP_CREATE_REG;
    pHeader->dwProcessId = GetCurrentProcessId();

    auto* pPayload = reinterpret_cast<CreateRegRequestPayload*>(requestBuf + sizeof(BrokerMessageHeader));
    pPayload->DesiredAccess        = DesiredAccess;
    pPayload->ObjAttributes        = ObjAttributes;
    pPayload->TitleIndex           = TitleIndex;
    pPayload->CreateOptions        = CreateOptions;
    pPayload->dwPathLengthBytes    = dwPathBytes;
    pPayload->dwClassLengthBytes   = dwClassBytes;
    BYTE* pDest = (BYTE*)pPayload->szData;
    memcpy(pDest, szNtPath, dwPathBytes);
    pDest += dwPathBytes;
    if (szClass && dwClassBytes > 0)
        memcpy(pDest, szClass, dwClassBytes);

    BYTE responseBuf[BROKER_MAX_MESSAGE_SIZE];
    DWORD dwResponseSize = 0;
    DWORD fStatus = Transact(requestBuf, dwRequestSize, responseBuf, sizeof(responseBuf), dwResponseSize);
    if (fStatus != ERROR_SUCCESS) return (NTSTATUS)STATUS_UNSUCCESSFUL;

    auto* pResp = reinterpret_cast<BrokerResponseHeader*>(responseBuf);
    if (NT_SUCCESS((NTSTATUS)pResp->dwStatus)) {
        *phHandle = (HANDLE)pResp->dwHandle;
        if (pDisposition &&
            dwResponseSize >= sizeof(BrokerResponseHeader) + sizeof(CreateRegResponsePayload)) {
            auto* pRespPayload = reinterpret_cast<CreateRegResponsePayload*>(
                responseBuf + sizeof(BrokerResponseHeader));
            *pDisposition = pRespPayload->Disposition;
        }
    }
    return (NTSTATUS)pResp->dwStatus;
}

NTSTATUS HookBrokerClient::OpenProcess(DWORD dwDesiredAccess, DWORD dwTargetPid, HANDLE* phHandle) {
    DWORD dwRequestSize = sizeof(BrokerMessageHeader) + sizeof(OpenProcessRequestPayload);

    BYTE requestBuf[sizeof(BrokerMessageHeader) + sizeof(OpenProcessRequestPayload)];
    auto* pHeader = reinterpret_cast<BrokerMessageHeader*>(requestBuf);
    pHeader->dwTotalSize = dwRequestSize;
    pHeader->dwRequestId = m_dwNextRequestId++;
    pHeader->dwOperation = BROKER_OP_OPEN_PROCESS;
    pHeader->dwProcessId = GetCurrentProcessId();

    auto* pPayload = reinterpret_cast<OpenProcessRequestPayload*>(requestBuf + sizeof(BrokerMessageHeader));
    pPayload->dwDesiredAccess    = dwDesiredAccess;
    pPayload->dwTargetProcessId  = dwTargetPid;

    BYTE responseBuf[sizeof(BrokerResponseHeader)];
    DWORD dwResponseSize = 0;
    DWORD fStatus = Transact(requestBuf, dwRequestSize, responseBuf, sizeof(responseBuf), dwResponseSize);
    if (fStatus != ERROR_SUCCESS) return (NTSTATUS)STATUS_UNSUCCESSFUL;

    auto* pResp = reinterpret_cast<BrokerResponseHeader*>(responseBuf);
    if (NT_SUCCESS((NTSTATUS)pResp->dwStatus))
        *phHandle = (HANDLE)pResp->dwHandle;
    return (NTSTATUS)pResp->dwStatus;
}

// ============================================================================
// Hook Setup and Teardown
// ============================================================================

static void InstallAllHooks() {
    // File operations
    InstallHook("NtCreateFile",              (PVOID)Hook_NtCreateFile,              (PVOID*)&Original_NtCreateFile);
    InstallHook("NtOpenFile",               (PVOID)Hook_NtOpenFile,               (PVOID*)&Original_NtOpenFile);
    InstallHook("NtDeleteFile",             (PVOID)Hook_NtDeleteFile,             (PVOID*)&Original_NtDeleteFile);
    InstallHook("NtQueryAttributesFile",    (PVOID)Hook_NtQueryAttributesFile,    (PVOID*)&Original_NtQueryAttributesFile);
    InstallHook("NtQueryFullAttributesFile",(PVOID)Hook_NtQueryFullAttributesFile,(PVOID*)&Original_NtQueryFullAttributesFile);

    // Registry operations
    InstallHook("NtOpenKey",          (PVOID)Hook_NtOpenKey,          (PVOID*)&Original_NtOpenKey);
    InstallHook("NtOpenKeyEx",        (PVOID)Hook_NtOpenKeyEx,        (PVOID*)&Original_NtOpenKeyEx);
    InstallHook("NtCreateKey",        (PVOID)Hook_NtCreateKey,        (PVOID*)&Original_NtCreateKey);
    InstallHook("NtQueryValueKey",    (PVOID)Hook_NtQueryValueKey,    (PVOID*)&Original_NtQueryValueKey);
    InstallHook("NtSetValueKey",      (PVOID)Hook_NtSetValueKey,      (PVOID*)&Original_NtSetValueKey);
    InstallHook("NtDeleteKey",        (PVOID)Hook_NtDeleteKey,        (PVOID*)&Original_NtDeleteKey);

    // Process operations
    InstallHook("NtOpenProcess",      (PVOID)Hook_NtOpenProcess,      (PVOID*)&Original_NtOpenProcess);

    // Subprocess propagation
    InstallHook("NtCreateUserProcess",(PVOID)Hook_NtCreateUserProcess,(PVOID*)&Original_NtCreateUserProcess);
    InstallHook("NtResumeThread",     (PVOID)Hook_NtResumeThread,     (PVOID*)&Original_NtResumeThread);

    // Resolve NtWriteFile/NtReadFile for broker pipe I/O (not hooked)
    // Resolve NtQueryObject for RootDirectory path resolution (not hooked)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    Original_NtWriteFile = (pfnNtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
    Original_NtReadFile  = (pfnNtReadFile) GetProcAddress(hNtdll, "NtReadFile");
    s_NtQueryObject      = (pfnNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
}

static void RemoveAllHooks() {
    for (DWORD i = 0; i < g_hookCount; i++) {
        RemoveInlineHook(g_hooks[i].pOriginalFunc, g_hooks[i].originalBytes, g_hooks[i].dwPatchSize);
        if (g_hooks[i].pTrampoline)
            VirtualFree(g_hooks[i].pTrampoline, 0, MEM_RELEASE);
    }
    g_hookCount = 0;
}

// ============================================================================
// DLL Entry Point
// ============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            g_hModule = hModule;
            DisableThreadLibraryCalls(hModule);

            // Store our own DLL path for subprocess injection
            GetModuleFileName(hModule, g_szHookDllPath, MAX_PATH);

            // Connect to the broker
            if (g_client.Connect() != ERROR_SUCCESS)
                return TRUE; // Don't block process start if broker not available

            InitializePendingChildrenState();

            // Install hooks
            InstallAllHooks();
            break;

        case DLL_PROCESS_DETACH:
            RemoveAllHooks();
            DestroyPendingChildrenState();
            g_client.Disconnect();
            break;
    }

    return TRUE;
}
