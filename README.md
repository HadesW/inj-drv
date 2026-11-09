# inj-drv

Windows 内核态 DLL 注入器：一个 WDM 驱动加一个用户态控制器，支持 x64 与
Wow64（32 位）目标。


## 功能

- **单一 IOCTL 分发**：所有命令走同一个 IOCTL 码，由请求信封里的 opcode
  分发（ping / 注入规则增删查 / IAT 还原 / 允许停止）。
- **三种注入方式**：
  - JMP：挂钩目标进程入口点，默认方式；
  - IAT：改写导入表，支持事后还原（`--iat`）；
  - APC：向目标线程投递用户 APC，Wow64 走内核路由 + `PsWrapApcWow64Thread`（`--apc`）。
- **规则匹配**：按 DLL 路径和 include/exclude 通配掩码决定注入哪些进程。
- **统一日志**：驱动、控制器、宿主进程、载荷 DLL 四类日志同一格式、同一目录。

## 目录

```
src/drv/          WDM 驱动（header-only）
  cmd/            opcode 处理：ping、注入规则、还原、allow-stop
  inject/         JMP / IAT / APC 三条注入路径
src/app/
  test-load/      用户态控制器 / 测试客户端
  test-dll/       测试载荷 DLL
  test-ui/        测试宿主（MFC 窗口）
src/shared/       协议定义与统一日志 logger.hpp（内核/用户态共用）
vsproject/        VS2026 解决方案（injector.slnx）
third/            crtsys 等第三方依赖（本地，不入库）
```

`third/` 是本地依赖，不会提交到仓库；构建前按工程配置放入对应目录。

## 构建

环境：Windows 10/11 x64、Visual Studio 2026、WDK 10.0.28000。

1. 用 VS2026 打开 `vsproject/injector.slnx`；
2. 选择 `Debug | x64`，构建整个解决方案；
3. 产物在 `bin/x64/Debug/`：`injdrv.sys`、`test-load.exe`、`test-dll.dll`、
   `test-ui.exe`。

32 位测试宿主和载荷（`test-dll`、`test-ui` 的 `Win32` 配置）不在解决方案里，
需要单独构建：

```bat
msbuild src\app\test-dll\test-dll.vcxproj -p:Configuration=Debug -p:Platform=Win32 ^
        -p:SolutionDir=<repo>\vsproject\
msbuild src\app\test-ui\test-ui.vcxproj -p:Configuration=Debug -p:Platform=Win32 ^
        -p:SolutionDir=<repo>\vsproject\
```

## 使用

驱动需要测试签名（或正式签名）后才能加载。

```bat
sc create injdrv type= kernel binPath= C:\path\to\injdrv.sys
sc start injdrv

:: 确认驱动已加载并校验协议身份
test-load.exe --ping

:: 给匹配 test-ui.exe 的进程注入 DLL（默认 JMP）
test-load.exe --add C:\injdrv\test-dll.dll --include test-ui.exe

:: IAT 注入，并在需要时还原
test-load.exe --add C:\injdrv\test-dll.dll --include test-ui.exe --iat
test-load.exe --restore

:: 查看 / 删除规则
test-load.exe --list
test-load.exe --remove C:\injdrv\test-dll.dll
```

`--include` / `--exclude` 接受通配掩码；`--restore [pid]` 不带 pid 时还原所有
仍在跟踪的进程。`test-load.exe [sys]` 的第一个非选项参数可指定驱动路径，
控制器会先装载驱动服务。

## 日志

四类日志统一写到 `C:\Windows\Temp\injdrv\`：

| 文件 | 来源 |
|---|---|
| `driver.log` | 内核驱动 |
| `loader.log` | test-load 控制器 |
| `target.log` | 测试宿主进程 |
| `payload.log` | 被注入的载荷 DLL |

行格式、级别、宏名和目录由 `src/shared/logger.hpp` 统一定义；驱动与用户态都使用
`LOG_TRACE/DEBUG/INFO/WARN/ERROR`，内核侧另有 `LOG_RAW`。时间均为本地时间：

```
[2026-10-17 23:09:15.426] [INFO ] [TARGET ] [pid 0x0C44 tid 0x0468] main.cpp:45 CTestUiApp::InitInstance() 测试窗口就绪 hwnd=0x450064
```

同时镜像到 DebugView（用户态 `OutputDebugString`、内核 `DbgPrintEx`）。

## 已验证

在测试虚拟机（testsigning）中跑完 x64 / Wow64 全矩阵：

| 方式 | 宿主 | 载荷 |
|---|---|---|
| JMP x64 | test-ui.exe | test-dll.dll |
| JMP x86 | test-ui32.exe | test-dll32.dll |
| JMP 多 DLL | test-ui.exe | test-dll.dll + test-dll2.dll |
| IAT x64 + 还原 | test-ui.exe | test-dll-iat64.dll |
| IAT x86 + 还原 | test-ui32.exe | test-dll-iat32.dll |
| APC x64 | apct64.exe | test-dll.dll |
| APC x86 | apct32.exe | test-dll32.dll |

测试载荷只用于验证：弹窗展示数秒后自动关闭并结束宿主进程。

## 限制

- 仅支持 Windows x64；32 位注入目标通过 Wow64 支持。
- 通知回调里只做记录，注入在独立系统线程 / 工作项里执行，避免在加载器
  深栈上做阻塞操作。
- 仅供授权环境下的测试与研究使用。
