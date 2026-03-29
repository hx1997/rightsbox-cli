//
// RBoxHook.h — Hook DLL injected into sandboxed processes.
// Contains NT native type declarations, inline hooking engine,
// broker client, and hooked function implementations.
//

#ifndef RIGHTSBOX_RBOXHOOK_H
#define RIGHTSBOX_RBOXHOOK_H

#include <windows.h>
#include "BrokerProtocol.h"

// ============================================================================
// NT Native Types (not in standard SDK headers)
// ============================================================================

typedef LONG NTSTATUS;

#define STATUS_SUCCESS           ((NTSTATUS)0x00000000)
#define STATUS_ACCESS_DENIED     ((NTSTATUS)0xC0000022)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)

#ifndef FILE_OPENED
#define FILE_OPENED              0x00000001
#endif

#ifndef THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#endif

#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE 0x00000000
#endif

#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif

#ifndef FILE_CREATE
#define FILE_CREATE 0x00000002
#endif

#ifndef FILE_OPEN_IF
#define FILE_OPEN_IF 0x00000003
#endif

#ifndef FILE_OVERWRITE
#define FILE_OVERWRITE 0x00000004
#endif

#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF 0x00000005
#endif

#ifndef FILE_WRITE_THROUGH
#define FILE_WRITE_THROUGH 0x00000002
#endif

#ifndef FILE_SEQUENTIAL_ONLY
#define FILE_SEQUENTIAL_ONLY 0x00000004
#endif

#ifndef FILE_NO_INTERMEDIATE_BUFFERING
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#endif

#ifndef FILE_RANDOM_ACCESS
#define FILE_RANDOM_ACCESS 0x00000800
#endif

#ifndef FILE_DELETE_ON_CLOSE
#define FILE_DELETE_ON_CLOSE 0x00001000
#endif

#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#endif

#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

// KEY_VALUE_INFORMATION_CLASS
#define KeyValuePartialInformation 2

// ============================================================================
// NT Function Pointer Typedefs
// ============================================================================

typedef NTSTATUS (NTAPI *pfnNtCreateFile)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
    PVOID EaBuffer, ULONG EaLength);

typedef NTSTATUS (NTAPI *pfnNtOpenFile)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions);

typedef NTSTATUS (NTAPI *pfnNtDeleteFile)(
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS (NTAPI *pfnNtQueryAttributesFile)(
    POBJECT_ATTRIBUTES ObjectAttributes, PVOID FileInformation);

typedef NTSTATUS (NTAPI *pfnNtQueryFullAttributesFile)(
    POBJECT_ATTRIBUTES ObjectAttributes, PVOID FileInformation);

typedef NTSTATUS (NTAPI *pfnNtOpenKey)(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS (NTAPI *pfnNtOpenKeyEx)(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions);

typedef NTSTATUS (NTAPI *pfnNtCreateKey)(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
    PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);

typedef NTSTATUS (NTAPI *pfnNtQueryValueKey)(
    HANDLE KeyHandle, PUNICODE_STRING ValueName,
    ULONG KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG Length, PULONG ResultLength);

typedef NTSTATUS (NTAPI *pfnNtSetValueKey)(
    HANDLE KeyHandle, PUNICODE_STRING ValueName,
    ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);

typedef NTSTATUS (NTAPI *pfnNtDeleteKey)(
    HANDLE KeyHandle);

typedef NTSTATUS (NTAPI *pfnNtOpenProcess)(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PVOID ClientId);

typedef NTSTATUS (NTAPI *pfnNtCreateUserProcess)(
    PHANDLE ProcessHandle, PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags, ULONG ThreadFlags,
    PVOID ProcessParameters, PVOID CreateInfo, PVOID AttributeList);

typedef NTSTATUS (NTAPI *pfnNtResumeThread)(
    HANDLE ThreadHandle, PULONG PreviousSuspendCount);

typedef NTSTATUS (NTAPI *pfnNtWriteFile)(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key);

typedef NTSTATUS (NTAPI *pfnNtReadFile)(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key);

// ============================================================================
// Inline Hooking Engine
// ============================================================================

struct HookEntry {
    const char* szFunctionName;     // e.g. "NtCreateFile"
    PVOID       pOriginalFunc;      // Address in ntdll
    PVOID       pDetourFunc;        // Our hook function
    PVOID       pTrampoline;        // Trampoline buffer (allocated)
    BYTE        originalBytes[32];  // Saved original bytes
    DWORD       dwPatchSize;        // Number of bytes patched
};

// Install an inline hook. Returns the trampoline (callable original).
PVOID InstallInlineHook(PVOID pTarget, PVOID pDetour, BYTE* pSavedBytes, DWORD* pdwPatchSize);

// Remove an inline hook (restore original bytes).
void RemoveInlineHook(PVOID pTarget, const BYTE* pSavedBytes, DWORD dwPatchSize);

// ============================================================================
// Broker Client (embedded in hook DLL)
// ============================================================================

class HookBrokerClient {
public:
    HookBrokerClient();
    ~HookBrokerClient();

    DWORD Connect();
    void Disconnect();

    DWORD Ping();
    DWORD Trace(const char* szMessage);
    DWORD OpenFile(LPCWSTR szPath, DWORD dwDesiredAccess, DWORD dwShareMode,
                   DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                   HANDLE* phHandle);
    DWORD DeleteFile(LPCWSTR szPath);
    DWORD QueryFile(LPCWSTR szPath, DWORD* pdwAttributes, ULONGLONG* pullSize,
                    FILETIME* pftCreation, FILETIME* pftLastWrite);
    DWORD OpenRegKey(DWORD dwRootKey, LPCWSTR szSubKey, DWORD dwDesiredAccess,
                     HANDLE* phHandle);
    DWORD QueryRegValue(DWORD dwRootKey, LPCWSTR szSubKey, LPCWSTR szValueName,
                        DWORD* pdwType, BYTE* pData, DWORD dwBufSize, DWORD* pdwDataSize);
    DWORD WriteRegValue(DWORD dwRootKey, LPCWSTR szSubKey, LPCWSTR szValueName,
                        DWORD dwType, const BYTE* pData, DWORD dwDataSize);
    DWORD OpenProcess(DWORD dwDesiredAccess, DWORD dwTargetPid, HANDLE* phHandle);

private:
    HANDLE m_hPipe;
    DWORD  m_dwNextRequestId;

    DWORD Transact(const BYTE* pRequest, DWORD dwRequestSize,
                   BYTE* pResponse, DWORD dwResponseBufSize, DWORD& dwResponseSize);
};

// ============================================================================
// Globals
// ============================================================================

extern HMODULE g_hModule;
extern WCHAR   g_szHookDllPath[MAX_PATH];
extern HookBrokerClient g_client;

// Thread-local flag to prevent hook recursion
extern __declspec(thread) BOOL g_bInBrokerCall;

#endif // RIGHTSBOX_RBOXHOOK_H
