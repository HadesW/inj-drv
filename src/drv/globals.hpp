// ============================================================================
// globals.hpp
// ----------------------------------------------------------------------------
// 驱动的全局状态全部放这里（xglobal 命名空间），初始化和清理统一走 init() /
// shutdown()。这样状态、生命周期、初始化顺序一眼可见，不用翻各处。
//
// 接线方式：
//   ntl::main 开头调 xglobal::initializer(driver)；
//   卸载路径调 xglobal::shutdown()。
//   以后要加的状态（注入规则表、通知回调句柄、统计计数等）直接往这里加。
// ============================================================================

#pragma once

#include <ntifs.h>

#include <ntl/device>
#include <ntl/driver>
#include <ntl/pool_allocator>
#include <ntl/symbolic_link>

#include <memory>
#include <memory_resource>
#include <mutex>
#include <vector>

#include "dispatch.hpp"
#include "../shared/logger.hpp"
#include "target.hpp"
#include "../shared/protocol.hpp"
#include "../shared/xheader.h"

namespace injdrv::xglobal {

// --- 状态 -------------------------------------------------------------------

// 驱动加载时刻（100ns 单位），用于计算运行时长。
inline ULONG64 load_tick = 0;

// ntl::main 收到的驱动对象。框架传引用，这里只留指针方便各处取用。
inline ntl::driver *driver = nullptr;

// 设备扩展，随设备对象生存。dispatcher 里的 remove_lock 要求稳定存储，所以
// 这块状态必须跟着设备走——不能放栈上、不能被移动或重建。
struct device_state {
  dispatcher dispatch;
  ntl::symbolic_link link;

  // 注入规则表。通知回调和 IOCTL 都在 PASSIVE_LEVEL 访问，std::mutex 足够
  // （crtsys 明确支持）；内存走非分页 pmr 池，容量按需增长，不再像老实现那样
  // 定长数组满了静默失败。
  std::mutex lock;
  ntl::pmr::pool_resource pool{ntl::pool_kind::nonpaged, "inJr"};
  std::pmr::vector<protocol::dll_item> rules{&pool};
  std::pmr::vector<target::record> targets{&pool};

  // 卸载开关。stop_denied 时 DriverUnload 被清空，cached_unload 保存原指针。
  bool allow_stop = true;
  bool stop_denied = false;
  PDRIVER_UNLOAD cached_unload = nullptr;
};

// 控制设备。从创建常驻到 shutdown()。
inline std::shared_ptr<ntl::device<device_state>> device;

// 日志走 src/shared/logger.hpp 的 logger 单例，初始化/关闭由下面的
// initializer()/shutdown() 负责，平时打日志直接用 LOG_* 宏。

// --- 生命周期 ---------------------------------------------------------------

// ntl::main 开头调用一次。初始化顺序就写在这里，不依赖静态初始化顺序。
inline void initializer(ntl::driver &drv) {
  KeQueryInterruptTimePrecise(&load_tick);
  driver = &drv;

  if (!log::logger::instance().ready()) {
    const bool opened = log::logger::instance().init(L"DRIVER");
    if (!opened) {
      DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                 "[injdrv] 日志文件打开失败，只输出到 DebugView\n");
    }
  }
}

// 卸载路径调用。顺序：先让在途请求跑完 -> 拆设备 -> 关日志。
inline void shutdown() noexcept {
  if (device)
    device->extension().dispatch.shutdown();
  device.reset();
  driver = nullptr;

  log::logger::instance().shutdown();
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[injdrv] 卸载完成\n");
}

} // namespace injdrv::xglobal
