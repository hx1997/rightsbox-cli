//
// Broker.h — Named pipe broker server for the sandbox.
//

#ifndef RIGHTSBOX_BROKER_H
#define RIGHTSBOX_BROKER_H

#include <windows.h>
#include <wincrypt.h>
#include "BrokerProtocol.h"
#include "BrokerPolicy.h"

class Broker {
public:
    Broker();
    ~Broker();

    // Initialize: create broker token, generate pipe name, build pipe security,
    // load policy. Must be called before Start(). hAdminToken is the current
    // process token (elevated admin).
    DWORD Initialize(HANDLE hAdminToken);

    // Start the listener thread. After this, clients can connect.
    DWORD Start();

    // Signal shutdown, clean up handles.
    DWORD Stop();

    // Returns the full pipe name for passing to the child process.
    LPCWSTR GetPipeName() const;

    // Access the policy engine (e.g. for adding rules before Start).
    BrokerPolicy& GetPolicy();

private:
    // --- Token ---
    HANDLE m_hBrokerToken;              // Medium-IL standard-user (LUA) token

    // --- Pipe ---
    WCHAR  m_szPipeName[128];
    SECURITY_ATTRIBUTES m_sa;
    PSECURITY_DESCRIPTOR m_pSD;
    PACL   m_pDacl;                     // Must outlive m_pSD
    PACL   m_pSacl;                     // Must outlive m_pSD
    PSID   m_pLogonIdSid;              // Extracted from admin token

    // --- Threading ---
    HANDLE m_hShutdownEvent;            // Manual-reset event, signaled to stop

    // --- Policy ---
    BrokerPolicy m_policy;

    // --- Internal methods ---
    DWORD CreateBrokerToken(HANDLE hAdminToken);
    DWORD ExtractLogonIdSid(HANDLE hToken);
    DWORD GeneratePipeName();
    DWORD BuildPipeSecurity();
    HANDLE CreatePipeInstance();

    static void ListenerThreadProc(Broker* pBroker);
    static void ClientThreadProc(Broker* pBroker, HANDLE hPipe);

    DWORD DispatchRequest(const BYTE* pRequestBuf, DWORD dwRequestSize,
                          BYTE* pResponseBuf, DWORD dwResponseBufSize,
                          DWORD& dwResponseSize);

    // Operation handlers
    DWORD HandlePing(DWORD dwRequestId, BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize);
    DWORD HandleOpenFile(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                         DWORD dwCallerPid, BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize);
    DWORD HandleDeleteFile(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                           BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize);
    DWORD HandleQueryFile(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                          BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize);
    DWORD HandleOpenReg(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                        DWORD dwCallerPid, BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize);
    DWORD HandleQueryReg(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                         BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize);
    DWORD HandleWriteReg(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                         BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize);
    DWORD HandleOpenProcess(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                            DWORD dwCallerPid, BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize);
    DWORD HandleTrace(const BYTE* pPayload, DWORD dwPayloadSize, DWORD dwRequestId,
                      DWORD dwCallerPid, BYTE* pResp, DWORD dwRespBufSize, DWORD& dwRespSize);

    // Helpers
    BOOL ValidatePath(LPCWSTR szPath, WCHAR* szCanonical, DWORD cchCanonical);

    static HKEY RootKeyFromId(DWORD dwRootKey);
};

#endif // RIGHTSBOX_BROKER_H
