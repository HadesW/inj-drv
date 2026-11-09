// ============================================================================
// target.hpp
// ----------------------------------------------------------------------------
// 进程跟踪槽。一个目标进程对应一条 record，记它的 pid、exe 名、各模块基址，
// 供后续注入步骤使用。
//
// 存在 xglobal::device_state::targets 里，所有访问都要拿 state.lock。
// exe_name 用定长缓冲，避免在通知回调里分配内存。
// ============================================================================

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "../shared/protocol.hpp"
#include "inject/iat.hpp"

namespace injdrv::target {

inline constexpr std::size_t max_name_chars = 64;

struct record {
  std::uint64_t pid = 0;
  std::uint64_t exe_base = 0;      // 主模块基址
  std::uint64_t ntdll_base = 0;    // 64 位 ntdll
  std::uint64_t ntdll32_base = 0;  // 32 位 ntdll（Wow64 目标）
  std::uint64_t apc_thread_id = 0; // APC 方式用的目标线程（首个线程）
  bool matched = false;            // 命中过注入规则
  bool injected = false;
  bool iat_active = false;         // IAT 注入过且还没还原
  bool is32 = false;               // Wow64 目标，走 PE32 路径
  inject::iat_restore_info iat{};  // 还原 IAT 所需的原始头字段
  std::array<wchar_t, max_name_chars> exe_name{};
};

// 把完整路径截成文件名并塞进定长缓冲，末尾强制补终止符。
inline void set_name(record &rec, std::wstring_view path) noexcept {
  if (const auto pos = path.find_last_of(L"\\/");
      pos != std::wstring_view::npos && pos + 1 < path.size()) {
    path.remove_prefix(pos + 1);
  }
  const std::size_t n = (std::min)(path.size(), max_name_chars - 1);
  std::copy_n(path.begin(), n, rec.exe_name.begin());
  rec.exe_name[n] = L'\0';
}

inline std::wstring_view name_of(const record &rec) noexcept {
  return rec.exe_name.data(); // 插入时保证了终止符
}

} // namespace injdrv::target
