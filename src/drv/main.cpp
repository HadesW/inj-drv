// ============================================================================
// main.cpp
// ----------------------------------------------------------------------------
// 驱动入口，只做接线：状态和生命周期都在 globals.hpp 的 xglobal 里，
// 业务逻辑去 src/drv/cmd/ 下加命令再注册进 dispatch。
// ============================================================================

#include "cmd/allow_stop.hpp"
#include "cmd/inject.hpp"
#include "cmd/ping.hpp"
#include "cmd/restore.hpp"
#include "globals.hpp"
#include "notify.hpp"

#include <ntl/driver>

ntl::status ntl::main(ntl::driver &driver, const std::wstring &registry_path) {
  (void)registry_path;

  injdrv::xglobal::initializer(driver);

  LOG_INFO(
      "injdrv 启动：driver_version=0x{:08X} protocol=0x{:04X} build=0x{:02X}",
      injdrv::protocol::driver_version, injdrv::protocol::protocol_version,
      injdrv::protocol::build_flags);

  ntl::device_options options;
  options.name(injdrv::protocol::device_name)
      .type(FILE_DEVICE_UNKNOWN)
      .exclusive(false);

  injdrv::xglobal::device =
      driver.create_device<injdrv::xglobal::device_state>(options);
  auto &state = *injdrv::xglobal::device;

  state.extension().dispatch.add<injdrv::cmd::ping_command,
                                 injdrv::cmd::handle_ping>();
  state.extension().dispatch.add<injdrv::cmd::inject_add_command,
                                 injdrv::cmd::handle_inject_add>();
  state.extension().dispatch.add<injdrv::cmd::inject_remove_command,
                                 injdrv::cmd::handle_inject_remove>();
  state.extension().dispatch.add<injdrv::cmd::inject_enum_command,
                                 injdrv::cmd::handle_inject_enum>();
  state.extension().dispatch.add<injdrv::cmd::restore_command,
                                 injdrv::cmd::handle_restore>();
  state.extension().dispatch.add<injdrv::cmd::allow_stop_command,
                                 injdrv::cmd::handle_allow_stop>();

  const auto linked = state.extension().link.create(
      injdrv::protocol::symlink_name_nt, injdrv::protocol::device_name_nt);
  if (!linked.is_ok()) {
    LOG_ERROR("符号链接创建失败：0x{:08X}",
              static_cast<ULONG>(static_cast<NTSTATUS>(linked)));
    return linked;
  }

  // 不捕获任何东西，直接取 xglobal::device，避免和设备扩展互相引用。
  state.on_borrowed_device_control(
      [](const ntl::device_control::code &code,
         const ntl::device_control::in_buffer &in,
         ntl::device_control::out_buffer &out) -> ntl::status {
        return injdrv::xglobal::device->extension().dispatch.dispatch(code, in,out);
      });

  driver.on_unload([]() {
    LOG_INFO("injdrv 卸载中");
    injdrv::notify::unregister_all();
    injdrv::xglobal::shutdown();
  });

  if (const auto registered = injdrv::notify::register_all();
      !registered.is_ok()) {
    return registered;
  }

  LOG_INFO("控制设备就绪：{} -> {}",
           injdrv::log::narrow(state.extension().link.name()),
           injdrv::log::narrow(state.extension().link.target_name()));
  return ntl::status::ok();
}
