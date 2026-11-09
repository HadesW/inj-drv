// ============================================================================
// match.hpp
// ----------------------------------------------------------------------------
// 进程名匹配：通配符 + '|' 分隔的掩码串。全部纯函数、不依赖内核 API，
// 所以能在用户态单测。驱动侧用它决定一条注入规则要不要作用于某个进程。
//
// 规则（与老实现一致）：
//   include_mask 为空 → 不匹配（必须显式列出目标）
//   exe 文件名须命中 include_mask，且不命中 exclude_mask
//   '*' 匹配任意长度，'?' 匹配单字符，大小写不敏感
// ============================================================================

#pragma once

#include <string_view>

namespace injdrv::match {

namespace detail {

constexpr wchar_t lower(wchar_t ch) noexcept {
  return (ch >= L'A' && ch <= L'Z') ? static_cast<wchar_t>(ch - L'A' + L'a') : ch;
}

constexpr bool equal_ci(wchar_t a, wchar_t b) noexcept {
  return lower(a) == lower(b);
}

} // namespace detail

// 大小写不敏感比较。
constexpr bool equals_ci(std::wstring_view a, std::wstring_view b) noexcept {
  if (a.size() != b.size())
    return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (!detail::equal_ci(a[i], b[i]))
      return false;
  }
  return true;
}

// 取路径里的文件名部分（最后一个 '\' 或 '/' 之后）。
constexpr std::wstring_view file_base(std::wstring_view path) noexcept {
  if (const auto pos = path.find_last_of(L"\\/");
      pos != std::wstring_view::npos) {
    path.remove_prefix(pos + 1);
  }
  return path;
}

// 通配符匹配。迭代式回溯，'*' 任意长度、'?' 单字符。
constexpr bool wildcard(std::wstring_view text, std::wstring_view mask) noexcept {
  std::size_t t = 0;
  std::size_t m = 0;
  std::size_t star = std::wstring_view::npos;
  std::size_t retry = 0;

  while (t < text.size()) {
    if (m < mask.size() && (mask[m] == L'?' || detail::equal_ci(mask[m], text[t]))) {
      ++t;
      ++m;
    } else if (m < mask.size() && mask[m] == L'*') {
      star = m++;
      retry = t;
    } else if (star != std::wstring_view::npos) {
      m = star + 1;
      t = ++retry;
    } else {
      return false;
    }
  }

  while (m < mask.size() && mask[m] == L'*')
    ++m;
  return m == mask.size();
}

// 掩码串：'|' 分隔，命中任一即真。空串返回 false。
constexpr bool any(std::wstring_view text, std::wstring_view masks) noexcept {
  if (masks.empty())
    return false;

  std::size_t start = 0;
  while (start <= masks.size()) {
    const auto sep = masks.find(L'|', start);
    const auto item = masks.substr(
        start, (sep == std::wstring_view::npos ? masks.size() : sep) - start);

    if (!item.empty() && wildcard(text, item))
      return true;

    if (sep == std::wstring_view::npos)
      break;
    start = sep + 1;
  }
  return false;
}

// 规则是否作用于该进程：include 必须命中，exclude 命中则排除。
constexpr bool should_inject(std::wstring_view exe_name,
                             std::wstring_view include_mask,
                             std::wstring_view exclude_mask) noexcept {
  if (include_mask.empty())
    return false;
  return any(exe_name, include_mask) && !any(exe_name, exclude_mask);
}

} // namespace injdrv::match
