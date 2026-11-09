// ============================================================================
// logger.hpp — 统一日志（内核/用户共用一份）
// ----------------------------------------------------------------------------
// 按编译环境自动选分支：内核工程的包含路径里有 WDK 的 ntifs.h，用户态没有，
// 所以 __has_include 就是分界线，工程文件不用加任何宏。两个分支对外接口完全
// 一致：injdrv::log::logger::instance().init(L"DRIVER"/L"LOADER"/…)，宏名同为
// LOG_TRACE/DEBUG/INFO/WARN/ERROR。行格式只在这里定义一次：
//
//   [2026-10-17 22:31:05.123] [INFO ] [DRIVER ] [pid 0x0004 tid 0x01A4] main.cpp:42 ntl::main() 消息
//
// 组件名（DRIVER/LOADER/TARGET/PAYLOAD）同时决定行内标签与文件名，日志统一
// 落在同一目录（\SystemRoot 与 C:\Windows 是同一处）\Temp\injdrv\：
//   driver.log / loader.log / target.log / payload.log
//
// IRQL 契约（内核侧）：LOG_* 会格式化并写文件，只允许 PASSIVE_LEVEL；更高
// IRQL 用 LOG_RAW，它只走 DbgPrint、不做任何分配。
// ============================================================================
#pragma once

#if defined(_KERNEL_MODE) || __has_include(<ntifs.h>)
#define INJDRV_LOG_KERNEL 1
// 必须排在任何 ntl 头之前，且用 ntifs.h（它会带上 ntddk.h/wdm.h）。
#include <ntifs.h>
#include <cstdarg>
#else
#define INJDRV_LOG_KERNEL 0
#include <windows.h>
#endif

#if INJDRV_LOG_KERNEL
#include <ntl/handle>
#include <ntl/unicode_string>
#endif

#include <cstdint>
#include <format>
#include <mutex>
#include <source_location>
#include <string>
#include <string_view>

namespace injdrv::log {

  // ===== 核心（两侧共有）===================================================

  enum class level : std::uint8_t { trace, debug, info, warn, error };

  constexpr std::string_view level_tag(level lvl) noexcept {
    switch (lvl) {
    case level::trace:
      return "TRACE";
    case level::debug:
      return "DEBUG";
    case level::info:
      return "INFO ";
    case level::warn:
      return "WARN ";
    case level::error:
      return "ERROR";
    }
    return "?????";
  }

  // 日志目录名，两侧各自加自己的根（内核 \SystemRoot，用户态 C:\Windows）。
  inline constexpr std::wstring_view directory_name = L"injdrv";

  inline std::string narrow(std::wstring_view wide) {
    std::string out;
    out.reserve(wide.size());
    for (const wchar_t ch : wide)
      out.push_back(ch < 0x80 ? static_cast<char>(ch) : '?');
    return out;
  }

  namespace detail {

    inline std::string_view file_name_of(const std::source_location& where) noexcept {
      std::string_view path = where.file_name();
      if (const auto pos = path.find_last_of("/\\");
        pos != std::string_view::npos && pos + 1 < path.size()) {
        path.remove_prefix(pos + 1);
      }
      return path;
    }

    inline std::string_view function_name_of(const std::source_location& where) noexcept {
      std::string_view name = where.function_name();

      if (const auto paren = name.find('('); paren != std::string_view::npos)
        name = name.substr(0, paren);
      while (!name.empty() && name.back() == ' ')
        name.remove_suffix(1);

      if (const auto space = name.find_last_of(' '); space != std::string_view::npos)
        name.remove_prefix(space + 1);

      return name;
    }

    // 唯一的时间戳格式；两侧只负责取出本地时间字段。
    inline std::string format_time(unsigned year, unsigned month, unsigned day,
      unsigned hour, unsigned minute, unsigned second,
      unsigned milliseconds) {
      return std::format("[{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}]",
        year, month, day, hour, minute, second, milliseconds);
    }

    // 文件名用的小写化：LOADER -> loader。
    inline std::wstring lower(std::wstring_view name) {
      std::wstring out(name);
      for (wchar_t& ch : out) {
        if (ch >= L'A' && ch <= L'Z')
          ch = static_cast<wchar_t>(ch - L'A' + L'a');
      }
      return out;
    }

  } // namespace detail

  // 唯一的行格式定义，两侧 write() 都必须走这里。
  inline std::string format_line(std::string_view timestamp, level lvl,
    std::string_view component, std::uint64_t pid,
    std::uint64_t tid, const std::source_location& where,
    std::string_view message) {
    return std::format("{} [{:<5}] [{:<7}] [pid 0x{:04X} tid 0x{:04X}] {}:{} {}() {}",
      timestamp, level_tag(lvl), component, pid, tid,
      detail::file_name_of(where), where.line(),
      detail::function_name_of(where), message);
  }

#if INJDRV_LOG_KERNEL

  // ===== 内核落地：DbgPrint + ZwWriteFile ==================================

  inline constexpr ULONG dpfltr_level(level lvl) noexcept {
    switch (lvl) {
    case level::error:
      return DPFLTR_ERROR_LEVEL;
    case level::warn:
      return DPFLTR_WARNING_LEVEL;
    case level::trace:
    case level::debug:
    case level::info:
      return DPFLTR_INFO_LEVEL;
    }
    return DPFLTR_INFO_LEVEL;
  }

  inline void enable_debug_output() noexcept {
    for (const ULONG level : { DPFLTR_ERROR_LEVEL, DPFLTR_WARNING_LEVEL,
                  DPFLTR_TRACE_LEVEL, DPFLTR_INFO_LEVEL })
      DbgSetDebugFilterState(DPFLTR_IHVDRIVER_ID, level, TRUE);
  }

  // 内核侧日志根：\SystemRoot 与用户态的 C:\Windows 指向同一目录。
  inline constexpr std::wstring_view log_directory = L"\\SystemRoot\\Temp\\injdrv";

  namespace detail {

    inline std::uint64_t current_pid() noexcept {
      return static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(PsGetCurrentProcessId()));
    }

    inline std::uint64_t current_tid() noexcept {
      return static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(PsGetCurrentThreadId()));
    }

    inline std::string timestamp() noexcept {
      LARGE_INTEGER now{};
      KeQuerySystemTimePrecise(&now);

      LARGE_INTEGER local{};
      ExSystemTimeToLocalTime(&now, &local);

      TIME_FIELDS fields{};
      RtlTimeToTimeFields(&local, &fields);

      return log::detail::format_time(
        fields.Year, fields.Month, fields.Day, fields.Hour,
        fields.Minute, fields.Second, fields.Milliseconds);
    }

    // ZwCreateFile 不会自建中间目录，先按文件路径把目录打开一次。
    inline NTSTATUS ensure_directory(const std::wstring& file_path) noexcept {
      const auto slash = file_path.find_last_of(L"\\/");
      if (slash == std::wstring::npos || slash == 0)
        return STATUS_SUCCESS;

      const std::wstring dir_path = file_path.substr(0, slash);
      ntl::unicode_string name{ dir_path };

      OBJECT_ATTRIBUTES attrs{};
      InitializeObjectAttributes(&attrs, &*name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr,
        nullptr);

      ntl::unique_handle handle;
      IO_STATUS_BLOCK io{};
      const NTSTATUS status = ZwCreateFile(
        handle.put(), FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attrs, &io, nullptr,
        FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        nullptr, 0);

      if (NT_SUCCESS(status))
        return STATUS_SUCCESS;
      if (status == STATUS_OBJECT_NAME_COLLISION ||
        status == STATUS_OBJECT_NAME_EXISTS)
        return STATUS_SUCCESS;
      return status;
    }

  } // namespace detail

  class logger {
  public:
    static logger& instance() noexcept {
      static logger instance;
      return instance;
    }

    logger(const logger&) = delete;
    logger& operator=(const logger&) = delete;

    // 组件名同时决定行内标签与文件名：<dir>\<component 小写>.log。
    // 文件打不开只降级为纯 DebugView 输出，由调用方决定是否致命。
    bool init(std::wstring_view component) noexcept {
      enable_debug_output();

      std::lock_guard<std::mutex> guard(mutex_);

      if (file_.valid())
        return true;

      component_ = narrow(component);
      path_ = std::wstring(log_directory) + L"\\" +
        log::detail::lower(component) + L".log";

      (void)detail::ensure_directory(path_);

      ntl::unicode_string name{ path_ };

      OBJECT_ATTRIBUTES attrs{};
      InitializeObjectAttributes(&attrs, &*name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

      IO_STATUS_BLOCK io{};
      const NTSTATUS status =
        ZwCreateFile(file_.put(), FILE_APPEND_DATA | SYNCHRONIZE, &attrs, &io,
          nullptr, FILE_ATTRIBUTE_NORMAL,
          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE |
            FILE_WRITE_THROUGH,
          nullptr, 0);
      if (!NT_SUCCESS(status)) {
        file_.reset();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
          "[injdrv] 日志文件打开失败: 0x%08X，只输出到 DebugView\n",
          status);
        return false;
      }
      return true;
    }

    void shutdown() noexcept {
      std::lock_guard<std::mutex> guard(mutex_);
      file_.reset();
      path_.clear();
    }

    bool ready() const noexcept { return file_.valid(); }

    const std::wstring& path() const noexcept { return path_; }

    void write(level lvl, const std::source_location& where,
      std::string_view message) noexcept {
      NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

      const std::string line = log::format_line(
        detail::timestamp(), lvl, component_, detail::current_pid(),
        detail::current_tid(), where, message);

      DbgPrintEx(DPFLTR_IHVDRIVER_ID, dpfltr_level(lvl), "[injdrv] %s\n",
        line.c_str());

      std::lock_guard<std::mutex> guard(mutex_);
      append_locked(line);
    }

  private:
    logger() = default;

    void append_locked(const std::string& line) noexcept {
      if (!file_.valid())
        return;

      const std::string with_eol = line + "\r\n";

      IO_STATUS_BLOCK io{};
      const NTSTATUS status =
        ZwWriteFile(file_.get(), nullptr, nullptr, nullptr, &io,
          const_cast<char*>(with_eol.data()),
          static_cast<ULONG>(with_eol.size()), nullptr, nullptr);
      if (!NT_SUCCESS(status))
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
          "[injdrv] log write failed: 0x%08X\n", status);
    }

    std::mutex mutex_;
    ntl::unique_handle file_;
    std::wstring path_;
    std::string component_ = "DRIVER";
  };

  // 任意 IRQL 可用：只走 DbgPrint，不做格式化以外的任何分配。
  inline void raw(const std::source_location& where, const char* fmt, ...) noexcept {
    const auto file = log::detail::file_name_of(where);
    const auto function = log::detail::function_name_of(where);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
      "[injdrv] [DRIVER ] %.*s:%u %.*s() ",
      static_cast<int>(file.size()), file.data(), where.line(),
      static_cast<int>(function.size()), function.data());

    va_list args;
    va_start(args, fmt);
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, fmt, args);
    va_end(args);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "\n");
  }

#else

  // ===== 用户态落地：OutputDebugString + WriteFile =========================

  inline std::wstring module_path(HMODULE module = nullptr) {
    wchar_t buffer[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(module, buffer, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
      return {};
    return std::wstring(buffer, length);
  }

  // 用户态日志根：C:\Windows 与内核侧的 \SystemRoot 指向同一目录。
  inline constexpr std::wstring_view log_directory = L"C:\\Windows\\Temp\\injdrv";

  namespace detail {

    inline std::string timestamp() {
      SYSTEMTIME now{};
      GetLocalTime(&now);
      return log::detail::format_time(
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute,
        now.wSecond, now.wMilliseconds);
    }

  } // namespace detail

  class logger {
  public:
    static logger& instance() noexcept {
      static logger instance;
      return instance;
    }

    logger(const logger&) = delete;
    logger& operator=(const logger&) = delete;

    // 组件名同时决定行内标签与文件名：<dir>\<component 小写>.log。
    bool init(std::wstring_view component) noexcept {
      std::lock_guard<std::mutex> guard(mutex_);

      if (valid_file())
        return true;

      component_ = narrow(component);
      path_ = std::wstring(log_directory) + L"\\" +
        log::detail::lower(component) + L".log";

      (void)CreateDirectoryW(log_directory.data(), nullptr);

      file_ = CreateFileW(path_.c_str(), FILE_APPEND_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
      return file_ != INVALID_HANDLE_VALUE;
    }

    void shutdown() noexcept {
      std::lock_guard<std::mutex> guard(mutex_);
      if (valid_file()) {
        CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
      }
      path_.clear();
      component_.clear();
    }

    bool ready() const noexcept { return valid_file(); }

    const std::wstring& path() const noexcept { return path_; }

    void write(level lvl, const std::source_location& where,
      std::string_view message) noexcept {
      try {
        const std::string line = log::format_line(
          detail::timestamp(), lvl, component_,
          static_cast<std::uint64_t>(GetCurrentProcessId()),
          static_cast<std::uint64_t>(GetCurrentThreadId()), where,
          message);

        const std::string debug_line = "[injdrv] " + line + "\n";
        OutputDebugStringA(debug_line.c_str());

        std::lock_guard<std::mutex> guard(mutex_);
        append_locked(line);
      }
      catch (...) {
        OutputDebugStringA("[injdrv] log format failed\n");
      }
    }

  private:
    logger() = default;

    // 手工映射时函数局部静态的构造可能被 CRT 的 TLS 快路径跳过，对象会是
    // 全零而不是走默认成员初始化，所以 0 也必须当成"未打开"。
    bool valid_file() const noexcept {
      return file_ != INVALID_HANDLE_VALUE && file_ != nullptr;
    }

    void append_locked(const std::string& line) noexcept {
      if (!valid_file())
        return;

      const std::string with_eol = line + "\r\n";
      DWORD written = 0;
      (void)WriteFile(file_, with_eol.data(),
        static_cast<DWORD>(with_eol.size()), &written, nullptr);
    }

    mutable std::mutex mutex_;
    HANDLE file_ = INVALID_HANDLE_VALUE;
    std::wstring path_;
    std::string component_;
  };

  // 进程/载荷入口处的一次性初始化：开日志并打一条启动行。
  inline void init_process(std::wstring_view component,
    std::string_view event = "进程启动") noexcept {
    logger& log = logger::instance();
    const bool file_ok = log.init(component);

    const std::wstring exe = module_path(nullptr);
    log.write(level::info, std::source_location::current(),
      std::format("{} exe={} pid=0x{:04X} bits={} log={} file={}", event,
        narrow(exe), static_cast<unsigned>(GetCurrentProcessId()),
        sizeof(void*) == 8 ? 64 : 32,
        narrow(log.path()), file_ok ? "ok" : "unavailable"));
  }

#endif // INJDRV_LOG_KERNEL

} // namespace injdrv::log

#define LOG_TRACE(...) ::injdrv::log::logger::instance().write(::injdrv::log::level::trace, std::source_location::current(), std::format(__VA_ARGS__))
#define LOG_DEBUG(...) ::injdrv::log::logger::instance().write(::injdrv::log::level::debug, std::source_location::current(), std::format(__VA_ARGS__))
#define LOG_INFO(...)  ::injdrv::log::logger::instance().write(::injdrv::log::level::info,  std::source_location::current(), std::format(__VA_ARGS__))
#define LOG_WARN(...)  ::injdrv::log::logger::instance().write(::injdrv::log::level::warn,  std::source_location::current(), std::format(__VA_ARGS__))
#define LOG_ERROR(...) ::injdrv::log::logger::instance().write(::injdrv::log::level::error, std::source_location::current(), std::format(__VA_ARGS__))

#if INJDRV_LOG_KERNEL
#define LOG_RAW(...) ::injdrv::log::raw(std::source_location::current(), __VA_ARGS__)
#endif

#undef INJDRV_LOG_KERNEL
