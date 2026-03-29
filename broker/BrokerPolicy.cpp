//
// BrokerPolicy.cpp — Regex-based policy engine implementation.
//

#include <cstdio>
#include <cwchar>
#include "BrokerPolicy.h"
#include "RBoxMessage.h"

BrokerPolicy::BrokerPolicy() {}

DWORD BrokerPolicy::AddRule(BrokerOperation op, PolicyAction action, LPCWSTR szPattern, BOOL bAnyOp) {
    Rule rule;
    rule.operation = op;
    rule.action = action;
    rule.bAnyOp = bAnyOp;

    // Check for wildcard path
    if (lstrcmpW(szPattern, L".*") == 0 || lstrcmpW(szPattern, L"*") == 0) {
        rule.bAnyPath = TRUE;
        // Still compile a dummy regex to keep the struct valid
        rule.pattern = std::wregex(L".*", std::regex_constants::icase);
    } else {
        rule.bAnyPath = FALSE;
        try {
            rule.pattern = std::wregex(szPattern,
                std::regex_constants::ECMAScript | std::regex_constants::icase);
        } catch (const std::regex_error &) {
            return ERROR_INVALID_PARAMETER;
        }
    }

    m_rules.push_back(rule);
    return ERROR_SUCCESS;
}

BOOL BrokerPolicy::IsAllowed(BrokerOperation op, LPCWSTR szCanonicalPath) const {
    for (size_t i = 0; i < m_rules.size(); i++) {
        const Rule &r = m_rules[i];

        // Check operation match
        if (!r.bAnyOp && r.operation != op)
            continue;

        // Check path match
        if (!r.bAnyPath) {
            if (!szCanonicalPath)
                continue;
            if (!std::regex_match(szCanonicalPath, r.pattern))
                continue;
        }

        // First match wins
        return (r.action == POLICY_ALLOW) ? TRUE : FALSE;
    }

    // Default deny
    return FALSE;
}

void BrokerPolicy::LoadDefaults() {
    m_rules.clear();

    // Allow ping unconditionally
    AddRule(BROKER_OP_PING, POLICY_ALLOW, L".*", FALSE);

    // Allow file reads from user profile and Windows directories
    AddRule(BROKER_OP_OPEN_FILE, POLICY_ALLOW, L"C:\\\\Users\\\\.*", FALSE);
    AddRule(BROKER_OP_QUERY_FILE, POLICY_ALLOW, L"C:\\\\Users\\\\.*", FALSE);
    AddRule(BROKER_OP_OPEN_FILE, POLICY_ALLOW, L"C:\\\\Windows\\\\.*", FALSE);
    AddRule(BROKER_OP_QUERY_FILE, POLICY_ALLOW, L"C:\\\\Windows\\\\.*", FALSE);

    // Deny file deletion in Windows directory
    AddRule(BROKER_OP_DELETE_FILE, POLICY_DENY, L"C:\\\\Windows\\\\.*", FALSE);

    // Allow registry reads
    AddRule(BROKER_OP_QUERY_REG, POLICY_ALLOW, L".*", FALSE);
    AddRule(BROKER_OP_OPEN_REG, POLICY_ALLOW, L".*", FALSE);

    // Allow process queries
    AddRule(BROKER_OP_OPEN_PROCESS, POLICY_ALLOW, L".*", FALSE);

    // Deny everything else
    AddRule(BROKER_OP_PING, POLICY_DENY, L".*", TRUE);
}

DWORD BrokerPolicy::LoadFromFile(LPCWSTR szConfigPath) {
    FILE *fp = _wfopen(szConfigPath, L"r");
    if (!fp)
        return GetLastError();

    m_rules.clear();

    char line[1024];
    int lineNum = 0;

    while (fgets(line, sizeof(line), fp)) {
        lineNum++;

        // Skip comments and blank lines
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '\n' || *p == '\r' || *p == '\0')
            continue;

        // Parse: <action> <operation> <regex_pattern>
        char szAction[32] = {};
        char szOp[32] = {};
        char szPattern[512] = {};

        if (sscanf(p, "%31s %31s %511[^\r\n]", szAction, szOp, szPattern) < 3) {
            char msg[128];
            sprintf(msg, "Broker policy: malformed rule at line %d", lineNum);
            IssueMessage(msg, MSGTYPE_WARNING);
            continue;
        }

        // Parse action
        PolicyAction action;
        if (_stricmp(szAction, "allow") == 0)
            action = POLICY_ALLOW;
        else if (_stricmp(szAction, "deny") == 0)
            action = POLICY_DENY;
        else {
            char msg[128];
            sprintf(msg, "Broker policy: unknown action '%s' at line %d", szAction, lineNum);
            IssueMessage(msg, MSGTYPE_WARNING);
            continue;
        }

        // Parse operation
        BOOL bAnyOp = FALSE;
        BrokerOperation op = BROKER_OP_PING;

        if (_stricmp(szOp, "*") == 0) {
            bAnyOp = TRUE;
        } else {
            // Convert to wide string for ParseOperation
            WCHAR wszOp[32];
            MultiByteToWideChar(CP_UTF8, 0, szOp, -1, wszOp, 32);
            if (!ParseOperation(wszOp, op)) {
                char msg[128];
                sprintf(msg, "Broker policy: unknown operation '%s' at line %d", szOp, lineNum);
                IssueMessage(msg, MSGTYPE_WARNING);
                continue;
            }
        }

        // Convert pattern to wide string
        WCHAR wszPattern[512];
        MultiByteToWideChar(CP_UTF8, 0, szPattern, -1, wszPattern, 512);

        // Trim trailing whitespace from pattern
        int len = lstrlenW(wszPattern);
        while (len > 0 && (wszPattern[len - 1] == L' ' || wszPattern[len - 1] == L'\t'))
            wszPattern[--len] = L'\0';

        DWORD fStatus = AddRule(op, action, wszPattern, bAnyOp);
        if (fStatus != ERROR_SUCCESS) {
            char msg[128];
            sprintf(msg, "Broker policy: invalid regex at line %d (error %lu)", lineNum, fStatus);
            IssueMessage(msg, MSGTYPE_WARNING);
        }
    }

    fclose(fp);
    return ERROR_SUCCESS;
}

BOOL BrokerPolicy::ParseOperation(LPCWSTR sz, BrokerOperation &op) {
    if (lstrcmpiW(sz, L"PING") == 0)           { op = BROKER_OP_PING; return TRUE; }
    if (lstrcmpiW(sz, L"OPEN_FILE") == 0)       { op = BROKER_OP_OPEN_FILE; return TRUE; }
    if (lstrcmpiW(sz, L"DELETE_FILE") == 0)      { op = BROKER_OP_DELETE_FILE; return TRUE; }
    if (lstrcmpiW(sz, L"QUERY_FILE") == 0)       { op = BROKER_OP_QUERY_FILE; return TRUE; }
    if (lstrcmpiW(sz, L"OPEN_REG") == 0)         { op = BROKER_OP_OPEN_REG; return TRUE; }
    if (lstrcmpiW(sz, L"QUERY_REG") == 0)        { op = BROKER_OP_QUERY_REG; return TRUE; }
    if (lstrcmpiW(sz, L"WRITE_REG") == 0)        { op = BROKER_OP_WRITE_REG; return TRUE; }
    if (lstrcmpiW(sz, L"OPEN_PROCESS") == 0)     { op = BROKER_OP_OPEN_PROCESS; return TRUE; }
    return FALSE;
}
