# RightsBox

**English** | [中文](README.zh-CN.md)

A lightweight, CLI-based, userspace sandbox for Windows using Job Objects, restricted tokens, and a broker-mediated hook architecture.

## How It Works

RightsBox separates **security** from **compatibility**: Windows security features lock down the sandboxed process's rights, while ntdll hooking and the broker restore controlled access to operations the process still needs.

### Security (rights lockdown)

The sandbox's security boundary is enforced entirely through the OS:

1. **Token restriction** — Strips admin group SIDs, adds restricting SIDs, and lowers the integrity level to Low. The sandboxed process simply *cannot* access protected resources — no hook bypass can change that.
2. **Job Object confinement** — Enforces UI limits and `KILL_ON_JOB_CLOSE` to contain the entire sandboxed process tree.

### Compatibility (hooking + broker)

A heavily restricted token breaks most programs. The hook layer restores selective access under policy control:

3. **Inline ntdll hooking** — Intercepts syscalls (`NtCreateFile`, `NtOpenFile`, `NtOpenKey`, `NtCreateUserProcess`, etc.) inside the sandboxed process. Operations that would fail due to the restricted token are caught before they hit the kernel.
4. **Broker-mediated policy** — Caught operations are forwarded over a named pipe to a medium-integrity broker running in the main process, which evaluates them against regex-based policy rules and performs them on behalf of the sandboxed process.

Child processes spawned inside the sandbox are automatically hooked, including cross-architecture scenarios (e.g., a 64-bit sandbox launching a 32-bit child).

## Components

| Binary | Role |
|---|---|
| `RightsBox.exe` | Main process (requires admin). Hosts the dispatcher, sandbox, and broker. |
| `RBoxRunner.exe` | Sandboxed launcher — spawned inside the sandbox with a restricted token, launches the user's target program. |
| `RBoxHook{64,32}.dll` | Hook DLL injected into every sandboxed process. Inline-hooks ntdll and routes blocked operations to the broker. |
| `RBoxInject{64,32}.exe` | Cross-architecture injection helper — used when a hooked process spawns a child of a different bitwidth. |

## Requirements

- Windows Vista or later (targets `_WIN32_WINNT=0x0600`)
- Administrator privileges
- Visual Studio 2022 Build Tools (MSVC, CMake)

## Building

### Quick build (x64 only)

```bash
cmake --preset vs2022-x64
cmake --build cmake-build-vs2022 --config Debug
```

Outputs: `cmake-build-vs2022/Debug/`

### Full cross-architecture build

```powershell
powershell -File build-all.ps1 -Configuration Debug
```

This builds both x64 and x86 targets and stages all artifacts into `dist/Debug/`.

### x86 only

```bash
cmake --preset vs2022-x86
cmake --build cmake-build-vs2022-x86 --config Debug
```

## Usage

### Interactive mode

```
RightsBox.exe
```

Presents a menu:
1. Run a program sandboxed
2. Run as... *(planned)*
3. Stop sandbox
4. Options *(planned)*
5. Exit

### Command-line mode

```
RightsBox.exe run_sandboxed <program_path> [args...]
```

Example:

```
RightsBox.exe run_sandboxed notepad.exe
RightsBox.exe run_sandboxed cmd.exe /k "echo Hello from sandbox"
```

## Policy Configuration

The broker uses a regex-based policy engine. Rules can be loaded from a `policy.conf` file or fall back to built-in defaults.

### Policy file format

```
# <action> <operation> <regex_pattern>
allow OPEN_FILE   C:\\Users\\.*
deny  DELETE_FILE  C:\\Windows\\.*
allow QUERY_REG   .*
deny  *           .*
```

- **Actions:** `allow`, `deny`
- **Operations:** `OPEN_FILE`, `DELETE_FILE`, `QUERY_FILE`, `OPEN_REG`, `QUERY_REG`, `WRITE_REG`, `OPEN_PROCESS`, `PING`, or `*` (any)
- First matching rule wins; default is deny

### Default policy

When no `policy.conf` is present, the built-in defaults:
- Allow file reads from `C:\Users\` and `C:\Windows\`
- Deny file deletion in `C:\Windows\`
- Allow registry reads and process queries
- Deny everything else

## Project Structure

```
rightsbox/     Main executable: entry point, dispatcher, sandbox setup, IOCP monitoring
broker/        Broker server: named pipe listener, policy engine, wire protocol
hook/          Hook DLL: inline ntdll hooks, embedded broker client
inject/        Cross-architecture injection helper
runner/        Sandboxed launcher (RBoxRunner)
utils/         Token manipulation and OS version utilities
```

## License

MIT License. See source files for details.
