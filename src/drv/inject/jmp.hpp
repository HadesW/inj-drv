// ============================================================================
// inject/jmp.hpp
// ----------------------------------------------------------------------------
// 入口点 JMP-hook 注入（x64 / Wow64）：改目标 exe 入口点前 12/5 字节跳到桩，
// 桩装载完 DLL 后还原原字节再跳回入口点继续执行。
//
// 32/64 只在桩生成、补丁编码和落点分配上不同，流程只写一遍。
// 失败路径全部靠 RAII 回滚（remote_memory 析构释放），不会在目标进程里留垃圾。
// ============================================================================

#pragma once

#include <ntifs.h>

#include <array>
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

// 把补丁点所在页永久改成 RWX，不恢复原保护。
// 桩在目标进程里运行时要往 patch_target 写回原 12 字节；如果这里把保护
// 改回 RX，桩一执行就访问违例，LdrLoadDll 根本跑不到。
inline bool make_patch_page_writable(HANDLE handle, void *address) noexcept {
  PVOID base = address;
  SIZE_T region = 0x1000;
  ULONG old = 0;
  const auto st = ZwProtectVirtualMemory(handle, &base, &region,
                                         PAGE_EXECUTE_READWRITE, &old);
  return NT_SUCCESS(st);
}

// 32 位桩必须落在 4GB 以下：优先跟着 exe 映像末尾，越界就退回 0x10000000。
template <bool Is32>
[[nodiscard]] inline ntl::result<process::remote_memory>
allocate_stub(HANDLE handle, PEPROCESS process, std::uint64_t exe_base) noexcept {
  if constexpr (!Is32) {
    return process::remote_memory::allocate(handle, shellcode::block_size);
  } else {
    auto headers = process::read_headers<true>(
        process, reinterpret_cast<const void *>(exe_base));
    if (!headers)
      return ntl::unexpected(headers.status());

    std::uintptr_t preferred =
        (static_cast<std::uintptr_t>(exe_base) +
         headers->nt.OptionalHeader.SizeOfImage + 0xFFFF) &
        ~std::uintptr_t{0xFFFF};
    if (preferred + shellcode::block_size > 0xFFFFFFFFull)
      preferred = 0x10000000;

    return process::allocate_below_4g(handle, preferred, shellcode::block_size);
  }
}

} // namespace detail

template <bool Is32>
inline ntl::status
inject_jmp_impl(PEPROCESS process, HANDLE handle, std::uint64_t exe_base,
                std::uint64_t ntdll_base,
                std::span<const std::wstring_view> dll_paths) noexcept {
  // 补丁点用 exe 入口点。NtTestAlert 只有线程进入 alertable 等待才跑，
  // 测试窗口内不一定被调用；exe 入口点一定执行，触发可靠。
  auto entry = process::find_entry_point<Is32>(
      process, reinterpret_cast<const void *>(exe_base));
  if (!entry) {
    LOG_WARN("JMP{}：取 exe 入口点失败：0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(static_cast<NTSTATUS>(entry.status())));
    return entry.status();
  }
  void *patch_target = *entry;

  auto ldr = process::find_export<Is32>(
      process, reinterpret_cast<const void *>(ntdll_base), "LdrLoadDll");
  if (!ldr) {
    LOG_WARN("JMP{}：找不到 LdrLoadDll：0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(static_cast<NTSTATUS>(ldr.status())));
    return ldr.status();
  }
  LOG_INFO("JMP{}：入口点=0x{:X} LdrLoadDll=0x{:X}", Is32 ? 32 : 64,
           reinterpret_cast<std::uint64_t>(patch_target),
           reinterpret_cast<std::uint64_t>(*ldr));

  auto allocation = detail::allocate_stub<Is32>(handle, process, exe_base);
  if (!allocation) {
    LOG_WARN("JMP{}：远程内存分配失败：0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(
                 static_cast<NTSTATUS>(allocation.status())));
    return allocation.status();
  }
  auto block = std::move(*allocation);
  const auto stub_base = reinterpret_cast<std::uint64_t>(block.get());

  // 读出被覆盖的原字节，桩里要还原。
  constexpr std::size_t patch_size =
      Is32 ? shellcode::patch_size32 : shellcode::patch_size;
  std::array<std::uint8_t, patch_size> original{};
  if (const auto st = process::read(process, patch_target, original.data(),
                                    original.size());
      !NT_SUCCESS(st)) {
    LOG_WARN("JMP{}：读取补丁点失败：0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(st));
    return ntl::status{st};
  }

  // 本地拼装桩与数据。13KB 不能放栈上，走池缓冲（分配即清零）。
  auto local_result =
      ntl::try_make_pool_buffer(shellcode::block_size, "inJs");
  if (!local_result) {
    LOG_WARN("JMP{}：桩缓冲分配失败", Is32 ? 32 : 64);
    return local_result.status();
  }
  auto local = std::move(*local_result);
  auto *stub = static_cast<std::uint8_t *>(local.get());

  if constexpr (Is32) {
    const auto target32 = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(patch_target));
    const auto ldr32 = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(*ldr));
    const auto base32 = static_cast<std::uint32_t>(stub_base);

    shellcode::build_jmp_stub32(stub, target32, ldr32, base32,
                                original.data());
    shellcode::write_payload32(stub, base32, dll_paths);
  } else {
    shellcode::build_jmp_stub64(stub,
                                reinterpret_cast<std::uint64_t>(patch_target),
                                reinterpret_cast<std::uint64_t>(*ldr),
                                stub_base, original.data());
    shellcode::write_payload(stub, stub_base, dll_paths);
  }

  if (const auto st = process::write(process, stub, block.get(),
                                     shellcode::block_size);
      !NT_SUCCESS(st)) {
    LOG_WARN("JMP{}：写入远程桩失败：0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(st));
    return ntl::status{st};
  }

  std::array<std::uint8_t, patch_size> hook{};
  if constexpr (Is32) {
    hook[0] = 0xE9; // jmp rel32
    const auto target32 = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(patch_target));
    const auto rel = static_cast<std::int32_t>(
        static_cast<std::int64_t>(static_cast<std::uint32_t>(stub_base)) -
        static_cast<std::int64_t>(target32 + shellcode::patch_size32));
    std::memcpy(hook.data() + 1, &rel, sizeof(rel));
  } else {
    hook[0] = 0x48;
    hook[1] = 0xB8; // mov rax, imm64
    const auto stub_addr = stub_base + shellcode::code_offset;
    std::memcpy(hook.data() + 2, &stub_addr, 8);
    hook[10] = 0xFF;
    hook[11] = 0xE0; // jmp rax
  }

  if (!detail::make_patch_page_writable(handle, patch_target)) {
    LOG_WARN("JMP{}：改页保护失败", Is32 ? 32 : 64);
    return ntl::status{STATUS_UNSUCCESSFUL};
  }

  if (const auto st =
          process::write(process, hook.data(), patch_target, hook.size());
      !NT_SUCCESS(st)) {
    LOG_WARN("JMP{}：写入补丁失败：0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(st));
    return ntl::status{st};
  }

  // 回读校验：确认补丁真的落到目标进程里了。
  std::array<std::uint8_t, patch_size> check{};
  if (const auto st =
          process::read(process, patch_target, check.data(), check.size());
      !NT_SUCCESS(st)) {
    LOG_WARN("JMP{}：回读补丁失败：0x{:08X}", Is32 ? 32 : 64,
             static_cast<ULONG>(st));
    return ntl::status{st};
  }
  const bool landed = std::memcmp(check.data(), hook.data(), hook.size()) == 0;

  std::uint64_t first = check[0];
  if constexpr (!Is32)
    std::memcpy(&first, check.data(), 8);
  // 补丁已指向桩，这块内存不能再释放（见 remote_memory::detach 注释）。
  block.detach();

  const auto stub_entry =
      Is32 ? stub_base : stub_base + shellcode::code_offset;
  LOG_INFO("JMP{} 补丁已写入：target=0x{:X} stub=0x{:X} 回读=0x{:016X} "
           "一致={}",
           Is32 ? 32 : 64,
           reinterpret_cast<std::uint64_t>(patch_target), stub_entry, first,
           landed ? 1 : 0);
  return ntl::status::ok();
}

inline ntl::status inject_jmp64(PEPROCESS process, HANDLE handle,
                                std::uint64_t exe_base,
                                std::uint64_t ntdll_base,
                                std::span<const std::wstring_view> dll_paths) noexcept {
  return inject_jmp_impl<false>(process, handle, exe_base, ntdll_base,
                                dll_paths);
}

inline ntl::status inject_jmp32(PEPROCESS process, HANDLE handle,
                                std::uint64_t exe_base,
                                std::uint64_t ntdll32_base,
                                std::span<const std::wstring_view> dll_paths) noexcept {
  return inject_jmp_impl<true>(process, handle, exe_base, ntdll32_base,
                               dll_paths);
}

} // namespace injdrv::inject
