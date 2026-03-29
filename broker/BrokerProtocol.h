//
// BrokerProtocol.h — Wire format shared between broker server (RightsBox.exe)
// and hook DLL (RBoxHook.dll).
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
    BROKER_OP_OPEN_FILE     = 1,    // Open file — returns duplicated handle
    BROKER_OP_DELETE_FILE   = 2,    // Delete file
    BROKER_OP_QUERY_FILE    = 3,    // Query file attributes/size
    BROKER_OP_OPEN_REG      = 4,    // Open registry key — returns duplicated handle
    BROKER_OP_QUERY_REG     = 5,    // Read registry value
    BROKER_OP_WRITE_REG     = 6,    // Write registry value
    BROKER_OP_OPEN_PROCESS  = 7,    // Open process — returns duplicated handle
    BROKER_OP_TRACE         = 8,    // Trace/log message from hook side
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
    DWORD     dwStatus;     // Win32 error code (ERROR_SUCCESS on success)
    DWORD_PTR dwHandle;     // Duplicated handle value (OPEN_FILE/OPEN_REG/OPEN_PROCESS), 0 if N/A
};

// --- Per-operation request payloads (appended after BrokerMessageHeader) ---

// BROKER_OP_OPEN_FILE
struct OpenFileRequestPayload {
    DWORD dwDesiredAccess;
    DWORD dwShareMode;
    DWORD dwCreationDisposition;
    DWORD dwFlagsAndAttributes;
    DWORD dwPathLengthBytes;    // Byte count of szPath including null terminator
    WCHAR szPath[1];            // Variable-length, null-terminated
};

// BROKER_OP_DELETE_FILE
struct DeleteFileRequestPayload {
    DWORD dwPathLengthBytes;
    WCHAR szPath[1];
};

// BROKER_OP_QUERY_FILE request
struct QueryFileRequestPayload {
    DWORD dwPathLengthBytes;
    WCHAR szPath[1];
};

// BROKER_OP_QUERY_FILE response payload (appended after BrokerResponseHeader)
struct QueryFileResponsePayload {
    DWORD     dwFileAttributes;
    ULONGLONG ullFileSize;
    FILETIME  ftCreationTime;
    FILETIME  ftLastWriteTime;
};

// BROKER_OP_OPEN_REG
struct OpenRegRequestPayload {
    DWORD dwRootKey;            // 0=HKLM, 1=HKCU, 2=HKCR, 3=HKU
    DWORD dwDesiredAccess;      // KEY_READ, KEY_WRITE, etc.
    DWORD dwSubKeyLengthBytes;
    WCHAR szSubKey[1];          // Variable-length, null-terminated
};

// BROKER_OP_QUERY_REG request
struct QueryRegRequestPayload {
    DWORD dwRootKey;
    DWORD dwSubKeyLengthBytes;
    DWORD dwValueNameLengthBytes;
    // Layout: WCHAR szSubKey[...] then WCHAR szValueName[...], consecutively
    WCHAR szData[1];
};

// BROKER_OP_QUERY_REG response payload
struct QueryRegResponsePayload {
    DWORD dwRegType;
    DWORD dwDataSize;
    BYTE  data[1];              // Variable-length registry value data
};

// BROKER_OP_WRITE_REG request
struct WriteRegRequestPayload {
    DWORD dwRootKey;
    DWORD dwRegType;
    DWORD dwSubKeyLengthBytes;
    DWORD dwValueNameLengthBytes;
    DWORD dwDataSize;
    // Layout: WCHAR szSubKey[...] then WCHAR szValueName[...] then BYTE data[dwDataSize]
    WCHAR szData[1];
};

// BROKER_OP_OPEN_PROCESS
struct OpenProcessRequestPayload {
    DWORD dwDesiredAccess;
    DWORD dwTargetProcessId;
};

// BROKER_OP_TRACE
struct TraceRequestPayload {
    DWORD dwMessageLengthBytes;
    CHAR  szMessage[1];
};

#pragma pack(pop)

#endif // RIGHTSBOX_BROKER_PROTOCOL_H
