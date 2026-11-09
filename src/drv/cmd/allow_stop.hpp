// ============================================================================
// cmd/allow_stop.hpp
// ----------------------------------------------------------------------------
// allow_stop：运行时决定驱动能否被 SCM 停止。
// crtsys 在 ntl::main 返回之后才把 DriverUnload 设成 CrtSysDriverUnload，
// 所以不能在 main 里预先清空；这里在 IOCTL 里先把原指针存进 xglobal，
// 再清空或恢复 DriverUnload。清空后 SCM 的 stop 会以失败告终，设备继续
// 可用来发 allow_stop 重新打开卸载。
// ============================================================================

#pragma once

#include <cstdint>

#include <ntl/status>

#include "../dispatch.hpp"
#include "../globals.hpp"

namespace injdrv::cmd {

using allow_stop_command = command<protocol::opcode::allow_stop,
                                   protocol::allow_stop_request,
                                   protocol::allow_stop_response>;

inline ntl::status handle_allow_stop(const protocol::allow_stop_request &req,
                                     protocol::allow_stop_response &resp) noexcept {
  const bool allow = req.allow != 0;

  auto &state = xglobal::device->extension();
  bool denied = false;
  {
    std::scoped_lock guard(state.lock);

    PDRIVER_OBJECT object = xglobal::driver->native_handle();
    if (allow) {
      if (state.stop_denied) {
        object->DriverUnload = state.cached_unload;
        state.cached_unload = nullptr;
        state.stop_denied = false;
      }
      state.allow_stop = true;
    } else {
      if (!state.stop_denied && object->DriverUnload != nullptr) {
        state.cached_unload = object->DriverUnload;
        object->DriverUnload = nullptr;
        state.stop_denied = true;
      }
      state.allow_stop = false;
    }

    resp.allowed = state.allow_stop ? 1 : 0;
    denied = state.stop_denied;
  }

  // 文件日志在锁外写，别把同步 IO 带进临界区。
  LOG_INFO("allow_stop：allowed={} stop_denied={}", resp.allowed,
           denied ? 1 : 0);
  return ntl::status::ok();
}

} // namespace injdrv::cmd
