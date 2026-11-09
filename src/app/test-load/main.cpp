// ============================================================================
// test-load/main.cpp
// ----------------------------------------------------------------------------
// 用户态控制器。装载驱动服务（可选）后通过唯一的 IOCTL 与驱动通信。
//
//   test-load [sys]                        默认发 ping
//   test-load [sys] --ping                 ping + 完整性验证
//   test-load [sys] --add <dll> --include <m> [--exclude <m>] [--iat|--apc]
//   test-load [sys] --remove <dll>
//   test-load [sys] --list
//   test-load [sys] --restore [pid]        pid 缺省或 0 表示还原所有进程
//   test-load [sys] --allow-stop on|off    允许/禁止 SCM 停止驱动
//
// 所有命令都走同一个 IOCTL 码，由请求信封里的 opcode 分发。
// ============================================================================

#include <windows.h>
#include <winioctl.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <random>
#include <string>
#include <string_view>

#include "../../shared/protocol.hpp"
#include "../../shared/logger.hpp"

namespace {

namespace p = injdrv::protocol;

constexpr wchar_t kServiceName[] = L"injdrv";
constexpr wchar_t kServiceDisplayName[] = L"injdrv injector";

// VM 上的 driver-lab 监听器按系统 ANSI 代码页解码控制台输出（中文是 936）。
// 日志文件保持 UTF-8，只有控制台镜像转成 ACP，中文才不会被拆成乱码、
// 也不会把紧跟全角标点的 ASCII 首字母吞掉。
void print_console(const char *prefix, std::string_view utf8) {
  if (utf8.empty()) {
    std::printf("%s\n", prefix);
    return;
  }

  const int utf8_len = static_cast<int>(utf8.size());
  const int wide_len =
      MultiByteToWideChar(CP_UTF8, 0, utf8.data(), utf8_len, nullptr, 0);
  std::wstring wide(static_cast<std::size_t>(wide_len), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, utf8.data(), utf8_len, wide.data(), wide_len);

  const int ansi_len =
      WideCharToMultiByte(CP_ACP, 0, wide.data(), wide_len, nullptr, 0, nullptr,
                          nullptr);
  std::string ansi(static_cast<std::size_t>(ansi_len), '\0');
  WideCharToMultiByte(CP_ACP, 0, wide.data(), wide_len, ansi.data(), ansi_len,
                      nullptr, nullptr);

  std::printf("%s %.*s\n", prefix, ansi_len, ansi.data());
}

// source_location 默认参数在调用点求值，调用方继续写 info(std::format(...))
// 也能让 loader.log 里记录真实的文件/行号。控制台格式保持不变。
void info(std::string_view line,
          const std::source_location &where =
              std::source_location::current()) {
  print_console("[+]", line);
  injdrv::log::logger::instance().write(injdrv::log::level::info, where, line);
}

void warn(std::string_view line,
          const std::source_location &where =
              std::source_location::current()) {
  print_console("[!]", line);
  injdrv::log::logger::instance().write(injdrv::log::level::warn, where, line);
}

// 宽转窄，非 ASCII 记 '?'。测试工具只打路径和掩码，够用。
std::string narrow(std::wstring_view wide) {
  std::string out;
  out.reserve(wide.size());
  for (const wchar_t ch : wide)
    out.push_back(ch < 0x80 ? static_cast<char>(ch) : '?');
  return out;
}

// 结果标记：虚拟机侧命令行要过 cmd.exe 的 OEM 代码页和一层引号包装，
// 中文输出和退出码都不可靠，所以另给一行纯 ASCII 供 tests/vm 判定。
int finish(int code) {
  std::puts(code == 0 ? "DRIVERLAB_RESULT=PASS" : "DRIVERLAB_RESULT=FAIL");
  LOG_INFO("命令结束 code={}", code);
  return code;
}

bool load_driver_service(const wchar_t *sys_path) {
  if (sys_path == nullptr || *sys_path == L'\0')
    return true;

  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
  if (scm == nullptr)
    return false;

  SC_HANDLE service =
      CreateServiceW(scm, kServiceName, kServiceDisplayName, SERVICE_ALL_ACCESS,
                     SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                     SERVICE_ERROR_NORMAL, sys_path, nullptr, nullptr, nullptr,
                     nullptr, nullptr);
  if (service == nullptr)
    service = OpenServiceW(scm, kServiceName, SERVICE_ALL_ACCESS);

  bool started = false;
  if (service != nullptr) {
    if (StartServiceW(service, 0, nullptr))
      started = true;
    else
      started = (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);
    CloseServiceHandle(service);
  }

  CloseServiceHandle(scm);
  return started;
}

class random_source {
public:
  std::uint64_t next() {
    return (static_cast<std::uint64_t>(source_()) << 32) | source_();
  }

private:
  std::random_device source_;
};

random_source g_random;

// 发一条命令并校验应答信封。命令级状态在 resp.header.status 里。
template <class Req, class Resp>
bool call(HANDLE device, p::opcode op, Req &req, Resp &resp) {
  req.header.size = static_cast<std::uint32_t>(sizeof(Req));
  req.header.opcode = static_cast<std::uint32_t>(op);
  req.header.request_id = g_random.next();

  DWORD returned = 0;
  if (!DeviceIoControl(device, p::control_code, &req, sizeof(req), &resp,
                       sizeof(resp), &returned, nullptr)) {
    warn(std::format("DeviceIoControl 失败：{}", GetLastError()));
    return false;
  }
  if (returned != sizeof(resp)) {
    warn(std::format("应答长度 {} 与预期 {} 不符", returned, sizeof(resp)));
    return false;
  }
  if (resp.header.request_id != req.header.request_id) {
    warn(std::format("request_id 不回显：发 0x{:016X} 收 0x{:016X}",
                     req.header.request_id, resp.header.request_id));
    return false;
  }
  if (resp.header.opcode != req.header.opcode) {
    warn(std::format("应答 opcode 0x{:X} 不符", resp.header.opcode));
    return false;
  }
  return true;
}

// --- ping：nonce + checksum 双向验证 -----------------------------------------
bool verify_ping(const p::ping_request &req, const p::ping_response &resp) {
  if (resp.header.status != 0) {
    warn(std::format("命令状态失败：0x{:08X}", resp.header.status));
    return false;
  }
  if (resp.nonce != req.nonce) {
    warn(std::format("nonce 不回显：发 0x{:016X} 收 0x{:016X}", req.nonce,
                     resp.nonce));
    return false;
  }
  if (resp.magic != p::reply_magic) {
    warn(std::format("magic 不符：0x{:08X}，应为 0x{:08X}", resp.magic,
                     p::reply_magic));
    return false;
  }
  if (resp.protocol != p::protocol_version) {
    warn(std::format("协议版本不符：驱动 0x{:04X}，本地 0x{:04X}", resp.protocol,
                     p::protocol_version));
    return false;
  }
  const std::uint64_t expected = p::ping_checksum(resp);
  if (resp.checksum != expected) {
    warn(std::format("checksum 不符：驱动 0x{:016X}，本地算 0x{:016X}",
                     resp.checksum, expected));
    return false;
  }
  return true;
}

int run_ping(HANDLE device) {
  p::ping_request req{};
  req.nonce = g_random.next();
  req.magic = p::request_magic;
  req.client_version = p::driver_version;

  p::ping_response resp{};
  info(std::format("发 ping：request_id=0x{:016X} nonce=0x{:016X}",
                   req.header.request_id, req.nonce));
  if (!call(device, p::opcode::ping, req, resp))
    return 1;
  if (!verify_ping(req, resp)) {
    warn("ping 验证未通过");
    return 1;
  }

  info(std::format("验证通过：driver_version=0x{:08X} protocol=0x{:04X} "
                   "build={} uptime={}ms",
                   resp.driver_version, resp.protocol,
                   resp.build_flags == p::build_debug ? "Debug" : "Release",
                   resp.uptime_ms));
  return 0;
}

// --- 注入规则 ---------------------------------------------------------------
void fill_item(p::dll_item &item, std::wstring_view dll, std::wstring_view include,
               std::wstring_view exclude) {
  p::init_dll_item(item);
  auto copy = [](wchar_t *dst, std::size_t cap, std::wstring_view src) {
    const std::size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
    src.copy(dst, n);
    dst[n] = L'\0';
  };
  copy(item.name, p::max_path_chars, dll);
  copy(item.include_mask, p::max_mask_chars, include);
  copy(item.exclude_mask, p::max_mask_chars, exclude);
}

int run_add(HANDLE device, std::wstring_view dll, std::wstring_view include,
            std::wstring_view exclude, bool iat, bool apc) {
  if (dll.empty() || include.empty()) {
    warn("--add 需要 DLL 路径和 --include 掩码");
    return 1;
  }

  p::inject_add_request req{};
  fill_item(req.item, dll, include, exclude);
  if (iat)
    req.item.flags |= p::inject_via_iat_patching;
  if (apc)
    req.item.flags |= p::inject_via_apc;
  p::inject_add_response resp{};
  if (!call(device, p::opcode::inject_add, req, resp))
    return 1;
  if (resp.header.status != 0) {
    warn(std::format("add 失败：0x{:08X}", resp.header.status));
    return 1;
  }

  info(std::format("add：accepted={} active_count={}", resp.accepted,
                   resp.active_count));
  return 0;
}

int run_remove(HANDLE device, std::wstring_view dll) {
  if (dll.empty()) {
    warn("--remove 需要 DLL 路径");
    return 1;
  }

  p::inject_remove_request req{};
  fill_item(req.item, dll, L"", L"");
  p::inject_remove_response resp{};
  if (!call(device, p::opcode::inject_remove, req, resp))
    return 1;
  if (resp.header.status != 0) {
    warn(std::format("remove 失败：0x{:08X}", resp.header.status));
    return 1;
  }

  info(std::format("remove：removed={} active_count={}", resp.removed,
                   resp.active_count));
  return 0;
}

int run_restore(HANDLE device, std::uint32_t pid) {
  p::restore_request req{};
  req.process_id = pid;
  p::restore_response resp{};
  if (!call(device, p::opcode::restore, req, resp))
    return 1;
  if (resp.header.status != 0) {
    warn(std::format("restore 失败：0x{:08X}", resp.header.status));
    return 1;
  }

  // 纯 ASCII：guest 端输出混合代码页时，全角标点会吞掉后面的 ASCII 字符，
  // 自动化判定只认这一行。
  info(std::format("restore: restored={} active={}", resp.restored,
                   resp.active));
  return 0;
}

int run_allow_stop(HANDLE device, bool allow) {
  p::allow_stop_request req{};
  req.allow = allow ? 1 : 0;
  p::allow_stop_response resp{};
  if (!call(device, p::opcode::allow_stop, req, resp))
    return 1;
  if (resp.header.status != 0) {
    warn(std::format("allow_stop 失败：0x{:08X}", resp.header.status));
    return 1;
  }

  info(std::format("allow_stop: allowed={}", resp.allowed));
  return 0;
}

int run_list(HANDLE device) {
  std::uint32_t count = 0;
  for (std::uint32_t index = 0;; ++index) {
    p::inject_enum_request req{};
    req.index = index;
    p::inject_enum_response resp{};
    if (!call(device, p::opcode::inject_enum, req, resp))
      return 1;
    if (resp.header.status != 0)
      break; // 越界即枚举结束

    // 定长数组在传输后可能没终止符，这里补一下再打印。
    resp.item.name[p::max_path_chars - 1] = L'\0';
    resp.item.include_mask[p::max_mask_chars - 1] = L'\0';
    resp.item.exclude_mask[p::max_mask_chars - 1] = L'\0';

    std::wstring name(resp.item.name);
    std::wstring include(resp.item.include_mask);
    std::wstring exclude(resp.item.exclude_mask);
    info(std::format("[{}] {} flags=0x{:04X} include={} exclude={}", index,
                     narrow(name), resp.item.flags, narrow(include),
                     narrow(exclude)));
    ++count;
  }

  info(std::format("共 {} 条规则", count));
  return 0;
}

} // namespace

int wmain(int argc, wchar_t **argv) {
  // 控制台输出按系统 ACP 编码（见 print_console），和监听器的解码口径一致。
  SetConsoleOutputCP(GetACP());
  injdrv::log::init_process(L"LOADER");
  LOG_INFO("命令行：{}", injdrv::log::narrow(GetCommandLineW()));

  const wchar_t *sys_path = nullptr;
  std::wstring action = L"--ping";
  std::wstring dll, include, exclude;
  bool iat = false;
  bool apc = false;
  bool allow_stop = false;
  std::uint32_t restore_pid = 0;

  for (int i = 1; i < argc; ++i) {
    const std::wstring_view arg = argv[i];
    if (arg == L"--ping" || arg == L"--list") {
      action = arg;
    } else if (arg == L"--iat") {
      iat = true;
    } else if (arg == L"--apc") {
      apc = true;
    } else if (arg == L"--restore") {
      action = arg;
      // 只有数字开头才当作 pid，避免把后面的驱动路径吃掉。
      if (i + 1 < argc) {
        const std::wstring_view next = argv[i + 1];
        if (!next.empty() && next[0] >= L'0' && next[0] <= L'9')
          restore_pid =
              static_cast<std::uint32_t>(std::wcstoul(argv[++i], nullptr, 0));
      }
    } else if (arg == L"--allow-stop" && i + 1 < argc) {
      action = arg;
      const std::wstring_view value = argv[++i];
      if (value == L"on" || value == L"1") {
        allow_stop = true;
      } else if (value == L"off" || value == L"0") {
        allow_stop = false;
      } else {
        warn("--allow-stop 只接受 on/off");
        return finish(1);
      }
    } else if (arg == L"--add" && i + 1 < argc) {
      action = arg;
      dll = argv[++i];
    } else if (arg == L"--remove" && i + 1 < argc) {
      action = arg;
      dll = argv[++i];
    } else if (arg == L"--include" && i + 1 < argc) {
      include = argv[++i];
    } else if (arg == L"--exclude" && i + 1 < argc) {
      exclude = argv[++i];
    } else if (arg == L"--dll" && i + 1 < argc) {
      dll = argv[++i];
    } else if (!arg.starts_with(L"--")) {
      sys_path = argv[i];
    } else {
      warn("未知参数");
      return finish(1);
    }
  }

  if (!load_driver_service(sys_path)) {
    warn(std::format("驱动服务装载失败：{}", GetLastError()));
    return finish(1);
  }
  if (sys_path != nullptr)
    info("驱动服务已运行");

  HANDLE device = CreateFileW(p::user_path, GENERIC_READ | GENERIC_WRITE, 0,
                              nullptr, OPEN_EXISTING, 0, nullptr);
  if (device == INVALID_HANDLE_VALUE) {
    warn(std::format("打开控制设备失败：{}", GetLastError()));
    return finish(1);
  }
  info("控制设备已打开");

  int result = 1;
  if (action == L"--ping") {
    result = run_ping(device);
  } else if (action == L"--add") {
    result = run_add(device, dll, include, exclude, iat, apc);
  } else if (action == L"--remove") {
    result = run_remove(device, dll);
  } else if (action == L"--list") {
    result = run_list(device);
  } else if (action == L"--restore") {
    result = run_restore(device, restore_pid);
  } else if (action == L"--allow-stop") {
    result = run_allow_stop(device, allow_stop);
  }

  CloseHandle(device);
  return finish(result);
}
