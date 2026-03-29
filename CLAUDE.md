# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RightsBox is a lightweight, CLI-based, userspace sandbox using Windows Job Objects, restricted tokens, and a broker-mediated hook architecture. Requires admin privileges, targets Windows Vista+ (`_WIN32_WINNT=0x0600`).

## Build

CMake-based build (C++11, MSVC, static CRT via `/MT`/`/MTd`). Four targets: `RightsBox.exe`, `RBoxRunner.exe`, `RBoxHook{32|64}.dll`, `RBoxInject{32|64}.exe`.

```bash
# x64 (primary)
cmake --preset vs2022-x64
cmake --build cmake-build-vs2022 --config Debug

# x86 (for cross-arch hook/inject artifacts)
cmake --preset vs2022-x86
cmake --build cmake-build-vs2022-x86 --config Debug

# Full cross-arch build + staging to dist/
powershell -File build-all.ps1 -Configuration Debug
```

Outputs land in `cmake-build-vs2022/Debug/` (x64) and `cmake-build-vs2022-x86/Debug/` (x86). The `build-all.ps1` script builds both architectures and stages all artifacts into `dist/<Config>/`.

Compile definitions: `WIN32`, `WINDOWS`, `UNICODE`, `_UNICODE`, `_WIN32_WINNT=0x0600`.

There are no tests or linting configured.

## Architecture

### Runtime components

| Binary | Role |
|---|---|
| `RightsBox.exe` | Main process (elevated admin). Hosts Dispatcher, Sandbox, Broker. |
| `RBoxRunner.exe` | Sandboxed launcher — spawned inside the sandbox with restricted token. Launches the user's target program. |
| `RBoxHook{64,32}.dll` | Hook DLL injected into every sandboxed process. Inline-hooks ntdll syscalls and routes blocked operations to the broker via named pipe. |
| `RBoxInject{64,32}.exe` | Cross-architecture injection helper — used when a hooked process spawns a child of different bitwidth. |

### Execution flow

1. **Entry:** `main.cpp` → `DispatchRoutineEntry()` (interactive menu) or `DispatchRunSandboxed(cmd)` (CLI: `RightsBox.exe run_sandboxed <program> [args]`)
2. **Sandbox setup** (`RBoxRun`): opens admin token → `RestrictToken()` strips admin groups/adds restricting SIDs/builds DACL → `SetTokenLowIL()` → launches `RBoxRunner.exe` suspended via `CreateProcessAsUser` → injects `RBoxHook.dll` via `CreateRemoteThread`+`LoadLibraryW` → confines to Job Object with UI limits and `KILL_ON_JOB_CLOSE` → monitors via IOCP
3. **Broker** (`broker/Broker`): runs in-process on a listener thread at medium-IL with a LUA token. Accepts named pipe connections from hook DLLs. Pipe name passed via `RIGHTSBOX_BROKER_PIPE` env var. DACL restricts pipe access to the admin token's LogonID SID. Dispatches file/registry/process operations after checking `BrokerPolicy`.
4. **Hook DLL** (`hook/RBoxHook`): on `DllMain` attach, connects to broker, installs inline trampoline hooks on ntdll functions (`NtCreateFile`, `NtOpenFile`, `NtDeleteFile`, `NtQueryAttributesFile`, `NtOpenKey`, `NtCreateKey`, `NtSetValueKey`, `NtOpenProcess`, `NtCreateUserProcess`, etc.). Denied operations are forwarded to the broker; allowed operations pass through the trampoline. `NtCreateUserProcess` hook propagates injection into child processes (same-arch direct, cross-arch via `RBoxInject`).
5. **Policy** (`broker/BrokerPolicy`): regex-based rules loaded from `policy.conf` or defaults. Each rule maps `(operation, path_regex)` → allow/deny. First match wins.

### Key modules

- `rightsbox/Dispatcher` — menu-driven CLI dispatcher; also exposes `DispatchRunSandboxed` for non-interactive use
- `rightsbox/RBoxRun` — `Sandbox` class (owns nested `Job` class) and `Broker` lifetime
- `rightsbox/RBoxIOCPNotifs` — IOCP polling for job notifications; terminates on magic value `0xCAFE`
- `rightsbox/RBoxInit` — OS version check (Vista+), admin check, UAC re-elevation via `ShellExecute runas`
- `rightsbox/RBoxMessage` — tagged console logging (`[INFO]`, `[WARNING]`, `[ERROR]`)
- `broker/BrokerProtocol.h` — packed wire format structs shared between broker and hook DLL
- `utils/TokenUtils` — `IsAdmin()`, `SetTokenLowIL()`, `SetTokenMediumIL()`, `RestrictToken()`

## Conventions

- Windows API types throughout (DWORD return codes, HANDLE, WCHAR, Win32 error codes)
- Error propagation via `GetLastError()` return values; `goto Cleanup` pattern for resource cleanup
- UNICODE build — string literals use `L""` prefix
- No third-party dependencies; pure Win32 API + C++ standard library
- Hook DLL uses `g_bInBrokerCall` thread-local flag to prevent hook recursion during broker pipe I/O
- Arch-suffixed output names (`RBoxHook64.dll`, `RBoxInject32.exe`) to support cross-architecture injection
