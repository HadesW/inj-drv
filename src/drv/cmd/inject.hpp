// ============================================================================
// cmd/inject.hpp
// ----------------------------------------------------------------------------
// 注入规则管理命令：增、删、枚举。本阶段只做规则表，不碰真正的注入。
//
// 锁约定：rules 只在 xglobal::device_state 里，所有访问都要拿 state.lock。
// 通知回调那边以后会并发读，所以这里统一用独占锁写。
// ============================================================================

#pragma once

#include <cstdint>

#include <ntl/status>

#include "../dispatch.hpp"
#include "../globals.hpp"
#include "../../shared/logger.hpp"
#include "../match.hpp"

namespace injdrv::cmd {

using inject_add_command =
    command<protocol::opcode::inject_add, protocol::inject_add_request,
            protocol::inject_add_response>;
using inject_remove_command =
    command<protocol::opcode::inject_remove, protocol::inject_remove_request,
            protocol::inject_remove_response>;
using inject_enum_command =
    command<protocol::opcode::inject_enum, protocol::inject_enum_request,
            protocol::inject_enum_response>;

namespace detail {

// 请求里的定长数组可能没写终止符，拷一份强制补上，避免后续遍历越界。
inline protocol::dll_item sanitized(const protocol::dll_item &src) noexcept {
  protocol::dll_item item = src;
  item.size = static_cast<std::uint32_t>(sizeof(protocol::dll_item));
  item.name[protocol::max_path_chars - 1] = L'\0';
  item.include_mask[protocol::max_mask_chars - 1] = L'\0';
  item.exclude_mask[protocol::max_mask_chars - 1] = L'\0';
  item.process_id = 0;
  return item;
}

inline bool empty_name(const protocol::dll_item &item) noexcept {
  return item.name[0] == L'\0';
}

} // namespace detail

inline ntl::status handle_inject_add(const protocol::inject_add_request &req,
                                     protocol::inject_add_response &resp) noexcept {
  const auto item = detail::sanitized(req.item);
  if (detail::empty_name(item))
    return STATUS_INVALID_PARAMETER;

  auto &state = xglobal::device->extension();
  std::scoped_lock guard(state.lock);

  for (const auto &existing : state.rules) {
    if (match::equals_ci(existing.name, item.name)) {
      resp.accepted = 0;
      resp.active_count = static_cast<std::uint32_t>(state.rules.size());
      LOG_INFO("规则已存在，忽略：{}", log::narrow(item.name));
      return ntl::status::ok();
    }
  }

  try {
    state.rules.push_back(item);
  } catch (...) {
    LOG_ERROR("规则表分配失败：{}", log::narrow(item.name));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  resp.accepted = 1;
  resp.active_count = static_cast<std::uint32_t>(state.rules.size());
  LOG_INFO("新增规则 #{}：include={} exclude={}", state.rules.size() - 1,
           log::narrow(item.include_mask), log::narrow(item.exclude_mask));
  return ntl::status::ok();
}

inline ntl::status
handle_inject_remove(const protocol::inject_remove_request &req,
                     protocol::inject_remove_response &resp) noexcept {
  const auto item = detail::sanitized(req.item);
  if (detail::empty_name(item))
    return STATUS_INVALID_PARAMETER;

  auto &state = xglobal::device->extension();
  std::scoped_lock guard(state.lock);

  for (auto it = state.rules.begin(); it != state.rules.end(); ++it) {
    if (match::equals_ci(it->name, item.name)) {
      state.rules.erase(it);
      resp.removed = 1;
      resp.active_count = static_cast<std::uint32_t>(state.rules.size());
      LOG_INFO("移除规则：{}", log::narrow(item.name));
      return ntl::status::ok();
    }
  }

  resp.removed = 0;
  resp.active_count = static_cast<std::uint32_t>(state.rules.size());
  LOG_WARN("移除失败，未找到：{}", log::narrow(item.name));
  return ntl::status::ok();
}

inline ntl::status handle_inject_enum(const protocol::inject_enum_request &req,
                                      protocol::inject_enum_response &resp) noexcept {
  auto &state = xglobal::device->extension();
  std::scoped_lock guard(state.lock);

  if (req.index >= state.rules.size()) {
    LOG_DEBUG("枚举越界：index={} count={}", req.index, state.rules.size());
    return STATUS_NO_MORE_ENTRIES;
  }

  resp.item = state.rules[req.index];
  resp.item.process_id = 0;
  return ntl::status::ok();
}

} // namespace injdrv::cmd
