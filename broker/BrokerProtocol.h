//
// BrokerProtocol.h — Wire format shared between broker server (RightsBox.exe)
// and hook DLL (RBoxHook.dll).
//
// All path fields carry NT namespace paths (e.g. \??\C:\Users\foo\bar.txt or
// \Registry\Machine\SOFTWARE\...).  The NT→Win32 conversion for policy matching
// happens once, on the broker side, keeping the hook side conversion-free.
//

#ifndef RIGHTSBOX_BROKER_PROTOCOL_H
#define RIGHTSBOX_BROKER_PROTOCOL_H

#include <windows.h>

// Maximum single message size (header + payload)
#define BROKER_MAX_MESSAGE_SIZE     (64 * 1024)

// Named pipe buffer sizes
#define BROKER_PIPE_BUFFER_SIZE     4096

// Environment variable name used to pass the pipe name to the sandboxed process
#define BROKER_PIPE_ENV_VAR         L"RIGHTSBOX_BROKER_PIPE"

// Pipe name prefix — full name is: prefix + PID + "_" + random hex
#define BROKER_PIPE_PREFIX          L"\\\\.\\pipe\\RightsBoxBroker_"

// Broker operations
enum BrokerOperation : DWORD {
    BROKER_OP_PING          = 0,    // Connectivity test
    BROKER_OP_OPEN_FILE     = 1,    // Open/create file — returns duplicated handle
    BROKER_OP_DELETE_FILE   = 2,    // Delete file
    BROKER_OP_QUERY_FILE    = 3,    // Query file attributes (FILE_NETWORK_OPEN_INFORMATION)
    BROKER_OP_OPEN_REG      = 4,    // Open registry key — returns duplicated handle
    BROKER_OP_QUERY_REG     = 5,    // Read registry value
    BROKER_OP_WRITE_REG     = 6,    // Write registry value
    BROKER_OP_OPEN_PROCESS  = 7,    // Open process — returns duplicated handle
    BROKER_OP_TRACE         = 8,    // Trace/log message from hook side
    BROKER_OP_CREATE_REG    = 9,    // Create registry key — returns duplicated handle + disposition
};

#pragma pack(push, 1)

// Request header — sent by the hook DLL to the broker
struct BrokerMessageHeader {
    DWORD dwTotalSize;      // Entire message including this header
    DWORD dwRequestId;      // Caller-assigned ID, echoed in response
    DWORD dwOperation;      // BrokerOperation value
    DWORD dwProcessId;      // Caller's PID — broker uses this for DuplicateHandle
};

// Response header — sent by the broker back to the hook DLL
struct BrokerResponseHeader {
    DWORD     dwTotalSize;  // Entire response including this header
    DWORD     dwRequestId;  // Echoed from request
    DWORD     dwStatus;     // NTSTATUS value (STATUS_SUCCESS on success)
    DWORD_PTR dwHandle;     // Duplicated handle value (OPEN_FILE/OPEN_REG/OPEN_PROCESS), 0 if N/A
};

// --- Per-operation request payloads (appended after BrokerMessageHeader) ---

// BROKER_OP_OPEN_FILE — covers both NtCreateFile and NtOpenFile.
// All parameters are raw NT values; the broker calls NtCreateFile directly.
struct OpenFileRequestPayload {
    ACCESS_MASK DesiredAccess;
    LONGLONG    AllocationSize;     // LARGE_INTEGER value; 0 when not specified
    ULONG       FileAttributes;     // NT file attributes
    ULONG       ShareAccess;
    ULONG       CreateDisposition;  // NT: FILE_OPEN, FILE_CREATE, FILE_OPEN_IF, etc.
    ULONG       CreateOptions;      // NT: FILE_SYNCHRONOUS_IO_NONALERT, etc.
    ULONG       ObjAttributes;      // OBJECT_ATTRIBUTES::Attributes (OBJ_CASE_INSENSITIVE, etc.)
    DWORD       dwPathLengthBytes;  // Byte count of szNtPath including null terminator
    WCHAR       szNtPath[1];        // NT namespace path, e.g. \??\C:\Users\foo\bar.txt
};

// BROKER_OP_OPEN_FILE response payload (appended after BrokerResponseHeader)
struct OpenFileResponsePayload {
    DWORD64     Information;        // IoStatusBlock.Information (FILE_OPENED, FILE_CREATED, etc.)
};

// BROKER_OP_DELETE_FILE
struct DeleteFileRequestPayload {
    ULONG       ObjAttributes;      // OBJECT_ATTRIBUTES::Attributes
    DWORD       dwPathLengthBytes;
    WCHAR       szNtPath[1];
};

// BROKER_OP_QUERY_FILE request
struct QueryFileRequestPayload {
    ULONG       ObjAttributes;      // OBJECT_ATTRIBUTES::Attributes
    DWORD       dwPathLengthBytes;
    WCHAR       szNtPath[1];
};

// BROKER_OP_QUERY_FILE response payload — mirrors FILE_NETWORK_OPEN_INFORMATION
struct QueryFileResponsePayload {
    LONGLONG  CreationTime;
    LONGLONG  LastAccessTime;
    LONGLONG  LastWriteTime;
    LONGLONG  ChangeTime;
    LONGLONG  AllocationSize;
    LONGLONG  EndOfFile;
    ULONG     FileAttributes;
    ULONG     _pad;
};

// BROKER_OP_OPEN_REG
// szNtPath is the full NT registry path: \Registry\Machine\... or \Registry\User\...
struct OpenRegRequestPayload {
    ACCESS_MASK DesiredAccess;
    ULONG       ObjAttributes;      // OBJECT_ATTRIBUTES::Attributes
    ULONG       OpenOptions;        // NtOpenKeyEx OpenOptions (0 for NtOpenKey behavior)
    DWORD       dwPathLengthBytes;
    WCHAR       szNtPath[1];
};

// BROKER_OP_QUERY_REG request
struct QueryRegRequestPayload {
    ULONG       ObjAttributes;
    DWORD       dwPathLengthBytes;      // NT registry path
    DWORD       dwValueNameLengthBytes;
    WCHAR       szData[1];              // [NtRegPath][ValueName] concatenated
};

// BROKER_OP_QUERY_REG response payload (appended after BrokerResponseHeader)
struct QueryRegResponsePayload {
    DWORD dwRegType;
    DWORD dwDataSize;
    BYTE  data[1];                      // Variable-length registry value data
};

// BROKER_OP_WRITE_REG request
struct WriteRegRequestPayload {
    ULONG       ObjAttributes;
    DWORD       dwRegType;
    DWORD       dwPathLengthBytes;
    DWORD       dwValueNameLengthBytes;
    DWORD       dwDataSize;
    WCHAR       szData[1];              // [NtRegPath][ValueName][BinaryData]
};

// BROKER_OP_OPEN_PROCESS
struct OpenProcessRequestPayload {
    DWORD dwDesiredAccess;
    DWORD dwTargetProcessId;
};

// BROKER_OP_CREATE_REG — covers NtCreateKey.
// Returns handle in BrokerResponseHeader.dwHandle + Disposition in response payload.
struct CreateRegRequestPayload {
    ACCESS_MASK DesiredAccess;
    ULONG       ObjAttributes;
    ULONG       TitleIndex;
    ULONG       CreateOptions;          // REG_OPTION_NON_VOLATILE, etc.
    DWORD       dwPathLengthBytes;
    DWORD       dwClassLengthBytes;     // 0 if no Class string
    WCHAR       szData[1];              // [NtRegPath][ClassString] concatenated
};

struct CreateRegResponsePayload {
    ULONG       Disposition;            // REG_CREATED_NEW_KEY or REG_OPENED_EXISTING_KEY
};

// BROKER_OP_TRACE
struct TraceRequestPayload {
    DWORD dwMessageLengthBytes;
    CHAR  szMessage[1];
};

#pragma pack(pop)

#endif // RIGHTSBOX_BROKER_PROTOCOL_H
