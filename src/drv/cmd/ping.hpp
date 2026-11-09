// ============================================================================
// cmd/ping.hpp
// ----------------------------------------------------------------------------
// ping：确认驱动已加载，并完成双向身份验证。
//   驱动 ← 客户端：magic 必须等于 request_magic，nonce 必须有值
//   客户端 ← 驱动：回显 nonce，返回版本/构建/运行时长，附带 checksum
// checksum 覆盖 nonce、uptime、magic、版本与构建标志，密钥是构建期常量——
// 客户端重算比对即可确认应答来自本项目构建的驱动，而不是别的同名设备。
// ============================================================================

#pragma once

#include <cstdint>

#include <ntl/status>

#include "../dispatch.hpp"
#include "../globals.hpp"

namespace injdrv::cmd {

using ping_command = command<protocol::opcode::ping, protocol::ping_request,
                             protocol::ping_response>;

inline ntl::status handle_ping(const protocol::ping_request &req,
                               protocol::ping_response &resp) noexcept {
  if (req.header.opcode !=
      static_cast<std::uint32_t>(protocol::opcode::ping)) {
    LOG_WARN("ping 信封 opcode 不符：0x{:X} (request_id=0x{:X})",
             req.header.opcode, req.header.request_id);
    return STATUS_INVALID_PARAMETER;
  }

  if (req.magic != protocol::request_magic) {
    LOG_WARN("ping magic 不符：0x{:08X}，应为 0x{:08X} (request_id=0x{:X})",
             req.magic, protocol::request_magic, req.header.request_id);
    return STATUS_REVISION_MISMATCH;
  }

  ULONG64 now = 0;
  KeQueryInterruptTimePrecise(&now);

  resp.nonce = req.nonce;
  resp.uptime_ms = (now - xglobal::load_tick) / 10000ull;
  resp.magic = protocol::reply_magic;
  resp.protocol = protocol::protocol_version;
  resp.driver_version = protocol::driver_version;
  resp.build_flags = protocol::build_flags;
  resp.checksum = protocol::ping_checksum(resp);

  LOG_INFO("ping 通过：nonce=0x{:016X} client_version=0x{:08X} uptime={}ms",
           resp.nonce, req.client_version, resp.uptime_ms);
  return ntl::status::ok();
}

} // namespace injdrv::cmd
