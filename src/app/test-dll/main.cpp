#include <windows.h>

#include <chrono>
#include <string>
#include <string_view>
#include <thread>

#include "../../shared/logger.hpp"

// Payload DLL：由驱动注入进目标进程。为了能自动化测试，行为是：
//   1. 统一日志写 C:\Windows\Temp\injdrv\payload.log（同时进 DebugView）
//   2. 落两个标记文件（<exe>.injected 和 C:\\injdrv\\payload-ok.txt）作为「注入成功」信号
//   3. 弹一个框给人眼看
//   4. 停留数秒后自动关掉弹框，再退出宿主进程，不留挂住的测试目标
// on_attach 在独立线程里跑，避开 DllMain 的 loader lock——日志初始化会碰
// 堆和文件系统，不能放在 DllMain 里。
namespace {

constexpr wchar_t kDialogTitle[] = L"injector";
constexpr DWORD kPopupVisibleMs = 3000; // 弹窗停留时长
constexpr DWORD kExitAfterCloseMs = 1000;

void write_marker_file(const std::wstring &path, std::string_view content) {
  const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    LOG_WARN("标记文件创建失败 path={} err={}", injdrv::log::narrow(path),
              GetLastError());
    return;
  }
  DWORD written = 0;
  (void)WriteFile(file, content.data(), static_cast<DWORD>(content.size()),
                  &written, nullptr);
  CloseHandle(file);
  LOG_INFO("标记文件已写入 path={} bytes={}", injdrv::log::narrow(path),
            written);
}

std::string marker_content(std::wstring_view tag) {
  return std::format("{} pid=0x{:04X} bits={}\r\n", injdrv::log::narrow(tag),
                     static_cast<unsigned>(GetCurrentProcessId()),
                     sizeof(void *) == 8 ? 64 : 32);
}

// 只用文档化 API：定时找到弹窗发 WM_CLOSE，然后结束宿主进程。
void close_popup_then_exit() {
  std::this_thread::sleep_for(std::chrono::milliseconds(kPopupVisibleMs));

  if (const HWND dialog = FindWindowW(L"#32770", kDialogTitle);
      dialog != nullptr) {
    LOG_INFO("弹窗计时结束，发送 WM_CLOSE");
    PostMessageW(dialog, WM_CLOSE, 0, 0);
  } else {
    LOG_WARN("弹窗计时结束但没找到窗口，直接退出宿主");
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(kExitAfterCloseMs));

  LOG_INFO("终止宿主进程 pid=0x{:04X}",
            static_cast<unsigned>(GetCurrentProcessId()));
  TerminateProcess(GetCurrentProcess(), 0);
}

// 按本 DLL 的文件名写标记：多 DLL 测试时能区分到底是哪一份载荷加载了。
void write_module_marker(HMODULE self) {
  const std::wstring path = injdrv::log::module_path(self);
  if (path.empty()) {
    LOG_WARN("取模块路径失败，跳过模块标记");
    return;
  }

  std::wstring name(path);
  if (const auto slash = name.find_last_of(L"\\/");
      slash != std::wstring::npos)
    name.erase(0, slash + 1);
  if (const auto dot = name.find_last_of(L'.'); dot != std::wstring::npos)
    name.erase(dot);
  if (name.empty())
    return;

  write_marker_file(L"C:\\injdrv\\payload-" + name + L".txt",
                    marker_content(L"test-dll injected"));
}

void on_attach(HMODULE self) {
  injdrv::log::init_process(L"PAYLOAD", "载荷附加");

  const std::wstring self_path = injdrv::log::module_path(self);
  const std::wstring host_path = injdrv::log::module_path(nullptr);
  LOG_INFO("DllMain PROCESS_ATTACH：dll={} host={}",
            injdrv::log::narrow(self_path), injdrv::log::narrow(host_path));

  const std::wstring host = host_path;
  if (!host.empty() && host.size() < MAX_PATH - 16) {
    std::wstring exe_marker = host;
    if (const auto dot = exe_marker.find_last_of(L'.');
        dot != std::wstring::npos)
      exe_marker.erase(dot);
    exe_marker += L".injected";
    write_marker_file(exe_marker, marker_content(L"test-dll injected"));
  }

  write_module_marker(self);
  write_marker_file(L"C:\\injdrv\\payload-ok.txt",
                    marker_content(L"test-dll has been injected."));

  LOG_INFO("载荷初始化完成，弹窗展示 {}ms 后自动退出宿主", kPopupVisibleMs);
  std::thread(close_popup_then_exit).detach();

  MessageBoxW(nullptr, L"test-dll has been injected.", kDialogTitle,
              MB_OK | MB_ICONINFORMATION);
}

} // namespace

// IAT 注入方式会把这条导入写进目标模块的导入表；加载器装载本 DLL 后要能解析
// 到这个符号，否则目标进程会因导入解析失败而启动失败。
extern "C" __declspec(dllexport) void injdrv_autoload(void) {}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(instance);
    std::thread([instance] { on_attach(instance); }).detach();
  }
  return TRUE;
}
