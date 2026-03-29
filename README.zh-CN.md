# RightsBox

[English](README.md) | **中文**

轻量级 Windows 用户态沙箱，基于命令行，通过 Job Objects、受限令牌与 Hook + 代理架构实现隔离。

## 工作原理

RightsBox 将**安全性**与**兼容性**解耦：系统安全机制负责从根本上收紧进程权限，ntdll Hook 与代理则在策略约束下按需放行合法操作。

### 安全性（权限收紧）

沙箱的安全边界完全由操作系统负责，无法被用户态代码绕过：

1. **令牌限制** — 剥离管理员组 SID，添加限制性 SID，将完整性级别降至 Low。沙箱进程从底层就*没有*访问受保护资源的能力，绕过 Hook 也改变不了这一点。
2. **Job Object 约束** — 强制施加 UI 限制并启用 `KILL_ON_JOB_CLOSE`，将整个沙箱进程树严格限制在 Job 内。

### 兼容性（Hook + 代理）

权限收得过死会导致大多数程序无法运行。Hook 层在策略管控下为进程补回必要的访问能力：

3. **ntdll 内联 Hook** — 在沙箱进程内拦截底层系统调用（`NtCreateFile`、`NtOpenFile`、`NtOpenKey`、`NtCreateUserProcess` 等），在请求到达内核之前截获那些因受限令牌而注定失败的操作。
4. **代理转发** — 被截获的操作通过命名管道发送至主进程中的中等完整性代理，由代理对照正则表达式策略规则裁决，并以自身权限代为执行。

沙箱内启动的子进程会自动被注入 Hook，跨架构场景同样支持（如 64 位沙箱启动 32 位子进程）。

## 组件

| 二进制文件 | 职责 |
|---|---|
| `RightsBox.exe` | 主进程（需管理员权限），承载调度器、沙箱和代理。 |
| `RBoxRunner.exe` | 沙箱内启动器，以受限令牌在沙箱中运行，负责拉起用户指定的目标程序。 |
| `RBoxHook{64,32}.dll` | Hook DLL，注入每个沙箱进程，对 ntdll 进行内联 Hook 并将截获的操作转发给代理。 |
| `RBoxInject{64,32}.exe` | 跨架构注入辅助程序，在被 Hook 进程创建不同位宽子进程时使用。 |

## 系统要求

- Windows Vista 及以上（目标平台 `_WIN32_WINNT=0x0600`）
- 管理员权限
- Visual Studio 2022 生成工具（MSVC、CMake）

## 构建

### 快速构建（仅 x64）

```bash
cmake --preset vs2022-x64
cmake --build cmake-build-vs2022 --config Debug
```

输出目录：`cmake-build-vs2022/Debug/`

### 完整跨架构构建

```powershell
powershell -File build-all.ps1 -Configuration Debug
```

同时构建 x64 与 x86，并将所有产物归集到 `dist/Debug/`。

### 仅 x86

```bash
cmake --preset vs2022-x86
cmake --build cmake-build-vs2022-x86 --config Debug
```

## 使用

### 交互模式

```
RightsBox.exe
```

启动后显示菜单：
1. 在沙箱中运行程序
2. 以指定身份运行…（*规划中*）
3. 停止沙箱
4. 选项（*规划中*）
5. 退出

### 命令行模式

```
RightsBox.exe run_sandboxed <程序路径> [参数...]
```

示例：

```
RightsBox.exe run_sandboxed notepad.exe
RightsBox.exe run_sandboxed cmd.exe /k "echo 来自沙箱的问候"
```

## 策略配置

代理内置基于正则表达式的策略引擎，可从 `policy.conf` 加载规则，缺省时使用内置默认策略。

### 策略文件格式

```
# <动作> <操作类型> <正则表达式>
allow OPEN_FILE   C:\\Users\\.*
deny  DELETE_FILE  C:\\Windows\\.*
allow QUERY_REG   .*
deny  *           .*
```

- **动作：** `allow`（放行）、`deny`（拒绝）
- **操作类型：** `OPEN_FILE`、`DELETE_FILE`、`QUERY_FILE`、`OPEN_REG`、`QUERY_REG`、`WRITE_REG`、`OPEN_PROCESS`、`PING`，或 `*`（匹配任意操作）
- 首条命中规则生效；未命中默认拒绝

### 内置默认策略

未提供 `policy.conf` 时：
- 允许读取 `C:\Users\` 和 `C:\Windows\` 下的文件
- 拒绝删除 `C:\Windows\` 下的文件
- 允许注册表读取与进程查询
- 其余一律拒绝

## 项目结构

```
rightsbox/     主程序：入口点、调度器、沙箱管理、IOCP 事件监控
broker/        代理：命名管道服务端、策略引擎、通信协议定义
hook/          Hook DLL：ntdll 内联 Hook、内嵌代理客户端
inject/        跨架构注入辅助程序
runner/        沙箱内启动器（RBoxRunner）
utils/         令牌操作、系统版本检测
```

## 许可证

MIT 许可证，详见源代码文件。
