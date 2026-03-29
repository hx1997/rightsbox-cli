//
// BrokerPolicy.h — Regex-based policy engine for the broker.
//

#ifndef RIGHTSBOX_BROKER_POLICY_H
#define RIGHTSBOX_BROKER_POLICY_H

#include <windows.h>
#include <regex>
#include <vector>
#include "BrokerProtocol.h"

enum PolicyAction : DWORD {
    POLICY_ALLOW = 0,
    POLICY_DENY  = 1,
};

class BrokerPolicy {
public:
    BrokerPolicy();

    // Add a rule. Pattern is an ECMAScript regex matched against the full path.
    // Use L".*" to match any path. opStr "*" matches any operation.
    DWORD AddRule(BrokerOperation op, PolicyAction action, LPCWSTR szPattern, BOOL bAnyOp = FALSE);

    // Check whether an operation on a canonical path is allowed.
    // Returns TRUE if allowed, FALSE if denied.
    BOOL IsAllowed(BrokerOperation op, LPCWSTR szCanonicalPath) const;

    // Load sensible default rules.
    void LoadDefaults();

    // Load rules from a config file. Returns ERROR_SUCCESS or a Win32 error.
    DWORD LoadFromFile(LPCWSTR szConfigPath);

private:
    struct Rule {
        BrokerOperation operation;
        PolicyAction    action;
        std::wregex     pattern;    // Compiled regex — case-insensitive
        BOOL            bAnyOp;     // TRUE = matches any operation
        BOOL            bAnyPath;   // TRUE = matches any path (optimization)
    };

    std::vector<Rule> m_rules;

    // Parse an operation name string to a BrokerOperation value.
    static BOOL ParseOperation(LPCWSTR sz, BrokerOperation &op);
};

#endif // RIGHTSBOX_BROKER_POLICY_H
