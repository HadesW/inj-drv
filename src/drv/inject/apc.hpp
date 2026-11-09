// ============================================================================
// inject/apc.hpp
// ----------------------------------------------------------------------------
// 用户态 APC 注入（x64 / Wow64）。在目标进程里分配一块 RWX 桩，写完
// LdrLoadDll 循环后，把桩地址作为 NormalRoutine 投递到目标线程；线程进入
// 可告警等待时桩执行，逐个装载 DLL，然后返回。
//
// 线程由调用方选定（notify 记录的目标首个线程）。APC 只在目标线程进入
// alertable 等待时才会送达。
//
// KAPC 生命周期：KeInsertQueueApc 成功后所有权交给内核——KernelRoutine 释放
// 已送达的 KAPC，RundownRoutine 释放线程退出时还没送达的，两条路互斥。
// ============================================================================

#pragma once

#include <ntifs.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

#include <ntl/pool_allocator>
#include <ntl/result>

#include "../../shared/logger.hpp"
#include "../process.hpp"
#include "../shellcode.hpp"

namespace injdrv::inject {

namespace detail {

// 当前 WDK 28000 的 wdm.h 只有 KAPC 结构，没有这些 APC 类型和函数声明。
extern "C" {
typedef VOID(NTAPI *apc_normal_routine)(PVOID NormalContext,
                                        PVOID SystemArgument1,
                                        PVOID SystemArgument2);
typedef VOID(NTAPI *apc_kernel_routine)(PKAPC Apc,
                                        apc_normal_routine *NormalRoutine,
                                        PVOID *NormalContext,
                                        PVOID *SystemArgument1,
                                        PVOID *SystemArgument2);
typedef VOID(NTAPI *apc_rundown_routine)(PKAPC Apc);

NTKERNELAPI VOID NTAPI KeInitializeApc(PKAPC Apc, PKTHREAD Thread,
                                       std::int32_t Environment,
                                       apc_kernel_routine KernelRoutine,
                                       apc_rundown_routine RundownRoutine,
                                       apc_normal_routine NormalRoutine,
                                       KPROCESSOR_MODE ApcMode,
                                       PVOID NormalContext);
NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(PKAPC Apc, PVOID SystemArgument1,
                                           PVOID SystemArgument2,
                                           KPRIORITY Increment);
}

inline constexpr std::int32_t original_apc_environment = 0;

// KAPC 送达后由内核在 APC_LEVEL 调用，释放自身占用的池块。
inline void NTAPI free_apc_kernel(PKAPC apc, apc_normal_routine *, PVOID *,
                                  PVOID *, PVOID *) noexcept {
  ntl::free_pool(apc, "inKa");
}

// 目标线程在 APC 送达前退出时调用。
inline void NTAPI free_apc_rundown(PKAPC apc) noexcept {
  ntl::free_pool(apc, "inKa");
}

// 分配 KAPC 并投递 x64 用户 APC。成功后所有权已交给内核。
inline ntl::status queue_user_apc(PETHREAD thread, void *stub) noexcept {
  auto created = ntl::try_make_pool<KAPC>("inKa");
  if (!created)
    return created.status();
  auto apc = std::move(*created);

  KeInitializeApc(apc.get(), reinterpret_cast<PKTHREAD>(thread),
                  original_apc_environment, free_apc_kernel, free_apc_rundown,
                  reinterpret_cast<apc_normal_routine>(stub), UserMode,
                  nullptr);
  if (!KeInsertQueueApc(apc.get(), nullptr, nullptr, 0))
    return ntl::status{STATUS_UNSUCCESSFUL};

  (void)apc.release();
  return ntl::status::ok();
}

// Wow64 路由请求：由目标线程里的内核 APC 消费。
// PsWrapApcWow64Thread 读的是“当前线程”的 Wow64 状态。系统线程即便挂靠
// 到目标进程，线程本身也不是 Wow64 线程，包装结果不可用（实测目标进程
// 执行桩时崩溃）。因此先给目标线程排一个内核 APC，在它的上下文里再包装
// 并投递用户 APC —— 与 wbenny/injdrv 的已验证路径一致。
struct wow64_apc_request {
  void *stub = nullptr;
};

inline void NTAPI route_wow64_apc(PVOID NormalContext, PVOID,
                                  PVOID) noexcept {
  auto *req = static_cast<wow64_apc_request *>(NormalContext);

  PVOID routine = req->stub;
  PVOID context = nullptr;
  const NTSTATUS wrapped = PsWrapApcWow64Thread(&context, &routine);
  if (NT_SUCCESS(wrapped)) {
    auto created = ntl::try_make_pool<KAPC>("inKa");
    if (created) {
      auto apc = std::move(*created);
      KeInitializeApc(apc.get(), PsGetCurrentThread(), original_apc_environment,
                      free_apc_kernel, free_apc_rundown,
                      reinterpret_cast<apc_normal_routine>(routine), UserMode,
                      context);
      if (KeInsertQueueApc(apc.get(), nullptr, nullptr, 0)) {
        (void)apc.release();
        LOG_INFO("APC32：Wow64 包装完成，用户 APC 已投递");
        ntl::free_pool(req, "inWr");
        return;
      }
    }
    LOG_WARN("APC32：投递用户 APC 失败");
  } else {
    LOG_WARN("APC32：PsWrapApcWow64Thread 失败 0x{:08X}",
             static_cast<ULONG>(wrapped));
  }

  ntl::free_pool(req, "inWr");
}

// 内核 APC 的 KernelRoutine 在 APC_LEVEL 运行，只释放 KAPC；NormalRoutine
// 随后在 PASSIVE_LEVEL 继续用局部拷贝执行，不再访问 KAPC。
inline void NTAPI route_apc_kernel(PKAPC apc, apc_normal_routine *, PVOID *,
                                   PVOID *, PVOID *) noexcept {
  ntl::free_pool(apc, "inKa");
}

inline void NTAPI route_apc_rundown(PKAPC apc) noexcept {
  if (apc->NormalContext != nullptr)
    ntl::free_pool(apc->NormalContext, "inWr");
  ntl::free_pool(apc, "inKa");
}

// 把 Wow64 路由 APC（内核态）排到目标线程，NormalRoutine 在目标线程上下文执行。
inline ntl::status queue_wow64_apc(PETHREAD thread, void *stub) noexcept {
  auto request = ntl::try_make_pool<wow64_apc_request>("inWr");
  if (!request)
    return request.status();
  auto req = std::move(*request);
  req->stub = stub;

  auto created = ntl::try_make_pool<KAPC>("inKa");
  if (!created)
    return created.status();
  auto apc = std::move(*created);

  KeInitializeApc(apc.get(), reinterpret_cast<PKTHREAD>(thread),
                  original_apc_environment, route_apc_kernel,
                  route_apc_rundown,
                  reinterpret_cast<apc_normal_routine>(route_wow64_apc),
                  KernelMode, req.get());
  if (!KeInsertQueueApc(apc.get(), nullptr, nullptr, 0))
    return ntl::status{STATUS_UNSUCCESSFUL};

  (void)apc.release();
  (void)req.release(); // 由 route_wow64_apc / route_apc_rundown 释放
  return ntl::status::ok();
}

// 32 位桩必须在 4GB 以下。
template <bool Is32>
[[nodiscard]] inline ntl::result<process::remote_memory>
allocate_apc_stub(HANDLE handle) noexcept {
  if constexpr (Is32)
    return process::allocate_below_4g(handle, 0x10000000,
                                      shellcode::block_size);
  else
    return process::remote_memory::allocate(handle, shellcode::block_size);
}

} // namespace detail

template <bool Is32>
inline ntl::status
inject_apc_impl(PEPROCESS process, HANDLE handle, std::uint64_t ntdll_base,
                PETHREAD thread,
                std::span<const std::wstring_view> dll_paths) noexcept {
  if (thread == nullptr || dll_paths.empty())
    return ntl::status{STATUS_INVALID_PARAMETER};

  auto ldr = process::find_export<Is32>(
      process, reinterpret_cast<const void *>(ntdll_base), "LdrLoadDll");
  if (!ldr) {
    LOG_WARN("APC{}：找不到 LdrLoadDll：0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(static_cast<NTSTATUS>(ldr.status())));
    return ldr.status();
  }

  auto allocation = detail::allocate_apc_stub<Is32>(handle);
  if (!allocation) {
    LOG_WARN("APC{}：远程内存分配失败：0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(
                 static_cast<NTSTATUS>(allocation.status())));
    return allocation.status();
  }
  auto block = std::move(*allocation);
  const auto base = reinterpret_cast<std::uintptr_t>(block.get());

  // 13KB 桩缓冲不能放栈上，走池缓冲（分配即清零）。
  auto local_result = [&] {
    if constexpr (Is32)
      return ntl::try_make_pool_buffer(shellcode::block_size, "inA3");
    else
      return ntl::try_make_pool_buffer(shellcode::block_size, "inA6");
  }();
  if (!local_result) {
    LOG_WARN("APC{}：桩缓冲分配失败", Is32 ? 32 : 64);
    return local_result.status();
  }
  auto local = std::move(*local_result);
  auto *stub = static_cast<std::uint8_t *>(local.get());

  if constexpr (Is32) {
    shellcode::build_apc_stub32(
        stub,
        static_cast<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(*ldr)),
        static_cast<std::uint32_t>(base));
    shellcode::write_payload32(stub, static_cast<std::uint32_t>(base),
                               dll_paths);
  } else {
    shellcode::build_apc_stub64(stub,
                                reinterpret_cast<std::uint64_t>(*ldr), base);
    shellcode::write_payload(stub, base, dll_paths);
  }

  if (const auto st =
          process::write(process, stub, block.get(), shellcode::block_size);
      !NT_SUCCESS(st)) {
    LOG_WARN("APC{}：写入远程桩失败：0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(st));
    return ntl::status{st};
  }

  const auto queued = Is32 ? detail::queue_wow64_apc(thread, block.get())
                           : detail::queue_user_apc(thread, block.get());
  if (!queued.is_ok()) {
    LOG_WARN("APC{}：投递失败 0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(static_cast<NTSTATUS>(queued)));
    return queued;
  }

  // 桩与数据要在目标进程里活到 APC 送达并执行完。
  block.detach();

  LOG_INFO("APC 已投递（{} 位）：stub=0x{:X} dlls={}", Is32 ? 32 : 64, base,
           dll_paths.size());
  return ntl::status::ok();
}

inline ntl::status inject_apc64(PEPROCESS process, HANDLE handle,
                                std::uint64_t ntdll_base, PETHREAD thread,
                                std::span<const std::wstring_view> dll_paths) noexcept {
  return inject_apc_impl<false>(process, handle, ntdll_base, thread,
                                dll_paths);
}

inline ntl::status inject_apc32(PEPROCESS process, HANDLE handle,
                                std::uint64_t ntdll32_base, PETHREAD thread,
                                std::span<const std::wstring_view> dll_paths) noexcept {
  return inject_apc_impl<true>(process, handle, ntdll32_base, thread,
                               dll_paths);
}

} // namespace injdrv::inject
