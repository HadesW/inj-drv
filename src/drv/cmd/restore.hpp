// ============================================================================
// cmd/restore.hpp
// ----------------------------------------------------------------------------
// 还原 IAT 注入：把目标模块的导入目录/BoundImports/校验和改回原值，并释放
// 追加的导入表区域。只处理跟踪槽里 iat_active 的进程。
//
// 锁约定：先在锁内把还原参数快照出来，跨进程 IO 全部在锁外做，完成后回锁
// 更新 iat_active。不要持锁调用 Zw*/KeStackAttachProcess。
// ============================================================================

#pragma once

#include <cstdint>
#include <memory_resource>
#include <mutex>

#include <ntl/status>

#include "../dispatch.hpp"
#include "../globals.hpp"
#include "../inject/iat.hpp"
#include "../../shared/logger.hpp"
#include "../process.hpp"
#include "../target.hpp"

namespace injdrv::cmd {

using restore_command =
    command<protocol::opcode::restore, protocol::restore_request,
            protocol::restore_response>;

inline ntl::status handle_restore(const protocol::restore_request &req,
                                  protocol::restore_response &resp) noexcept {
  auto &state = xglobal::device->extension();

  struct job {
    std::uint64_t pid = 0;
    std::uint64_t module_base = 0;
    inject::iat_restore_info info{};
  };

  std::pmr::vector<job> jobs{&state.pool};
  try {
    std::scoped_lock guard(state.lock);
    jobs.reserve(state.targets.size());
    for (const auto &rec : state.targets) {
      if (!rec.iat_active)
        continue;
      if (req.process_id != 0 && rec.pid != req.process_id)
        continue;
      jobs.push_back(job{rec.pid, rec.exe_base, rec.iat});
    }
    // 锁内认领，避免两个并发 restore 对同一块导入表重复释放。
    for (auto &rec : state.targets) {
      if (!rec.iat_active)
        continue;
      if (req.process_id != 0 && rec.pid != req.process_id)
        continue;
      rec.iat_active = false;
      rec.iat = {};
    }
  } catch (...) {
    LOG_ERROR("还原任务分配失败");
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  std::uint32_t restored = 0;
  // 失败就把认领还回去，下次还能重试。pid 可能已被复用，用 exe 基址再确认
  // 是同一条记录；进程已退出的话记录早被删了，循环自然找不到。
  const auto release_claim = [&state](const job &j) {
    std::scoped_lock guard(state.lock);
    for (auto &rec : state.targets) {
      if (rec.pid == j.pid && rec.exe_base == j.module_base) {
        rec.iat = j.info;
        rec.iat_active = true;
        break;
      }
    }
  };

  for (const auto &j : jobs) {
    auto process = process::open_process(reinterpret_cast<HANDLE>(j.pid));
    if (!process) {
      LOG_WARN("还原：打开目标进程失败 pid=0x{:X} 0x{:08X}", j.pid,
               static_cast<ULONG>(static_cast<NTSTATUS>(process.status())));
      release_claim(j);
      continue;
    }

    const auto status = inject::restore_iat(
        process->process(), process->native_handle(),
        reinterpret_cast<void *>(j.module_base), j.info);

    if (!status.is_ok()) {
      LOG_WARN("还原失败 pid=0x{:X} 0x{:08X}", j.pid,
               static_cast<ULONG>(static_cast<NTSTATUS>(status)));
      release_claim(j);
      continue;
    }

    ++restored;
  }

  {
    std::scoped_lock guard(state.lock);
    std::uint32_t active = 0;
    for (const auto &rec : state.targets) {
      if (rec.iat_active)
        ++active;
    }
    resp.active = active;
  }
  resp.restored = restored;

  LOG_INFO("还原完成：restored={} active={}", resp.restored, resp.active);
  return ntl::status::ok();
}

} // namespace injdrv::cmd
