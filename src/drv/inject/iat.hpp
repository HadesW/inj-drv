// ============================================================================
// inject/iat.hpp
// ----------------------------------------------------------------------------
// IAT 注入：在 ImageBase+SizeOfImage 之后找一块空页，把原 import_descriptor
// 数组复制过去再追加一条指向我们的 hint/name，然后改 NT 头的导入表目录指过
// 去。加载器初始化时就会按新表装载我们的 DLL。
//
// 32/64 位只差 PE 头类型、thunk 宽度和地址上限，统一收在
// inject_iat_impl<Is32> / restore_iat_impl<Is32> 里，公共入口按 is32 分派。
// 资源全部 RAII：远程区域走 remote_memory、表缓冲走 pool_buffer、头页保护
// 走 page_protection，失败路径不会在目标进程或内核里留下垃圾。
//
// 改的是 PE 数据不是代码，没有 shellcode，也不需要桩内存。
// ============================================================================

#pragma once

#include <ntifs.h>
#include <ntimage.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include <ntl/pool_allocator>
#include <ntl/result>
#include <ntl/status>

#include "../../shared/logger.hpp"
#include "../process.hpp"

namespace injdrv::inject {

// 还原一次 IAT 注入所需的原始字段。
struct iat_restore_info {
  std::uint32_t import_va = 0;
  std::uint32_t import_size = 0;
  std::uint32_t bound_va = 0;
  std::uint32_t bound_size = 0;
  std::uint32_t checksum = 0;
  void *region = nullptr;
  std::size_t region_size = 0;
  bool is32 = false; // PE32 模块（Wow64 目标），还原时走 32 位路径
};

namespace detail {

inline constexpr std::uintptr_t page_mask = 0xFFF;
inline constexpr SIZE_T header_region_size = 0x2000;
inline constexpr std::size_t max_import_descriptors = 64;
inline constexpr std::size_t max_table_bytes = 0x3000;
inline constexpr std::size_t table_region_size = 0x1000;
inline constexpr std::uintptr_t allocation_step = 0x10000;
inline constexpr std::uintptr_t allocation_scan_limit = 0x4000000;

// 把目标模块头页改成可写，析构时恢复原保护。restore() 幂等，调用方想在
// 成功路径上尽早恢复也可以显式调一次。
class page_protection {
public:
  page_protection(HANDLE handle, const void *base, SIZE_T size,
                  ULONG protect) noexcept
      : handle_(handle),
        base_(reinterpret_cast<PVOID>(reinterpret_cast<std::uintptr_t>(base) &
                                      ~page_mask)),
        size_(size) {
    PVOID address = base_;
    SIZE_T region = size_;
    ULONG old = 0;
    status_ = ZwProtectVirtualMemory(handle_, &address, &region, protect, &old);
    if (NT_SUCCESS(status_)) {
      base_ = address;
      size_ = region;
      old_protect_ = old;
    }
  }

  page_protection(const page_protection &) = delete;
  page_protection &operator=(const page_protection &) = delete;

  ~page_protection() { restore(); }

  bool valid() const noexcept { return NT_SUCCESS(status_); }
  NTSTATUS status() const noexcept { return status_; }

  void restore() noexcept {
    if (!valid() || restored_)
      return;
    restored_ = true;

    PVOID address = base_;
    SIZE_T region = size_;
    ULONG ignored = 0;
    (void)ZwProtectVirtualMemory(handle_, &address, &region, old_protect_,
                                 &ignored);
  }

private:
  HANDLE handle_ = nullptr;
  PVOID base_ = nullptr;
  SIZE_T size_ = 0;
  ULONG old_protect_ = 0;
  NTSTATUS status_ = STATUS_UNSUCCESSFUL;
  bool restored_ = false;
};

// 新导入表在目标进程里的布局：
//   [描述符数组（含结尾全零项）][INT thunk + 0][IAT thunk + 0][dll 名][hint + 函数名]
// thunk 宽度由 pe_traits 决定（64 位 8 字节，32 位 4 字节）。
template <bool Is32> struct import_table_layout {
  using thunk = typename process::pe_traits<Is32>::thunk;

  std::size_t descriptors = 0;
  std::size_t int_offset = 0;
  std::size_t iat_offset = 0;
  std::size_t name_offset = 0;
  std::size_t hint_offset = 0;
  std::size_t total = 0;

  import_table_layout(std::size_t existing_count, std::size_t name_length,
                      std::size_t func_length) noexcept {
    constexpr std::size_t thunk_array = sizeof(thunk) * 2; // 一项 + 终止 0

    descriptors = (existing_count + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    int_offset = descriptors;
    iat_offset = int_offset + thunk_array;
    name_offset = iat_offset + thunk_array;
    hint_offset = name_offset + name_length + 1;
    total = hint_offset + sizeof(std::uint16_t) + func_length + 1;
  }
};

} // namespace detail

// --- 注入 -------------------------------------------------------------------
template <bool Is32>
inline ntl::status inject_iat_impl(PEPROCESS target, HANDLE handle,
                                   void *module_base, std::string_view dll_name,
                                   std::string_view import_func,
                                   iat_restore_info *restore_out) noexcept {
  if (module_base == nullptr || dll_name.empty() || import_func.empty())
    return STATUS_INVALID_PARAMETER;

  auto headers = process::read_headers<Is32>(target, module_base);
  if (!headers)
    return headers.status();

  auto &nt = headers->nt;
  const IMAGE_DATA_DIRECTORY import_dir =
      nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  const IMAGE_DATA_DIRECTORY bound_dir =
      nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
  const std::uint32_t original_checksum = nt.OptionalHeader.CheckSum;

  // 读现有 import_descriptor，遇到全零项（终止符）为止。
  std::array<IMAGE_IMPORT_DESCRIPTOR, detail::max_import_descriptors> existing{};
  std::size_t existing_count = 0;
  if (import_dir.VirtualAddress != 0) {
    for (std::size_t i = 0; i < existing.size(); ++i) {
      IMAGE_IMPORT_DESCRIPTOR descriptor{};
      const auto *at = static_cast<const std::uint8_t *>(module_base) +
                       import_dir.VirtualAddress +
                       i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
      if (!NT_SUCCESS(process::read(target, at, &descriptor, sizeof(descriptor))))
        break;
      if (descriptor.Name == 0 && descriptor.FirstThunk == 0 &&
          descriptor.OriginalFirstThunk == 0)
        break;
      existing[existing_count++] = descriptor;
    }
  }

  const detail::import_table_layout<Is32> layout{
      existing_count, dll_name.size(), import_func.size()};
  if (layout.total > detail::max_table_bytes)
    return STATUS_INVALID_PARAMETER;

  // 从模块映像末尾开始按 64K 向上找空位。固定基址的 exe（如 notepad 的
  // 0x140000000）映像后面经常已经有堆/映射占着，只试首选地址会直接失败。
  // 新表的 RVA 必须落在 [0, 4G) 内，所以扫描范围限制在模块上方 64MB。
  const auto module_va = reinterpret_cast<std::uintptr_t>(module_base);
  const std::uintptr_t preferred =
      (module_va + nt.OptionalHeader.SizeOfImage + 0xFFFF) &
      ~std::uintptr_t{0xFFFF};

  process::remote_memory region;
  for (std::uintptr_t offset = 0; offset <= detail::allocation_scan_limit;
       offset += detail::allocation_step) {
    const std::uintptr_t candidate = preferred + offset;

    if constexpr (Is32) {
      // 32 位代码只能寻址低 4GB，区域连同表尾都必须放得下。
      if (candidate + layout.total > 0xFFFFFFFFull)
        break;
    } else {
      // 新导入表目录里存的是 32 位 RVA，整张表都必须能在 RVA 空间里表示。
      if (candidate - module_va + layout.total > 0x1'0000'0000ull)
        break;
    }

    auto block = process::remote_memory::allocate(
        handle, detail::table_region_size,
        reinterpret_cast<void *>(candidate), PAGE_READWRITE);
    if (block) {
      region = std::move(*block);
      break;
    }
    if (static_cast<NTSTATUS>(block.status()) !=
        STATUS_CONFLICTING_ADDRESSES) {
      LOG_WARN("IAT 区域分配失败：0x{:08X}",
               static_cast<ULONG>(static_cast<NTSTATUS>(block.status())));
      return block.status();
    }
  }
  if (region.get() == nullptr) {
    LOG_WARN("IAT 区域分配失败：0x{:08X}",
             static_cast<ULONG>(STATUS_CONFLICTING_ADDRESSES));
    return STATUS_CONFLICTING_ADDRESSES;
  }

  const auto region_va = reinterpret_cast<std::uintptr_t>(region.get());
  const auto make_rva = [module_va, region_va](std::size_t offset) noexcept {
    return static_cast<std::uint32_t>(region_va + offset - module_va);
  };

  // 拼装新导入表。布局保证结尾描述符和名字串的终止符都显式写零，不依赖
  // 池分配是否清零。
  auto buffer = ntl::try_make_pool_buffer(layout.total, "inIb");
  if (!buffer) {
    LOG_WARN("IAT 表缓冲分配失败：0x{:08X}",
             static_cast<ULONG>(static_cast<NTSTATUS>(buffer.status())));
    return buffer.status();
  }
  auto *bytes = static_cast<std::uint8_t *>(buffer->get());
  std::memset(bytes, 0, layout.total);

  for (std::size_t i = 0; i < existing_count; ++i)
    std::memcpy(bytes + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), &existing[i],
                sizeof(IMAGE_IMPORT_DESCRIPTOR));

  IMAGE_IMPORT_DESCRIPTOR ours{};
  ours.OriginalFirstThunk = make_rva(layout.int_offset);
  ours.Name = make_rva(layout.name_offset);
  ours.FirstThunk = make_rva(layout.iat_offset);
  std::memcpy(bytes + existing_count * sizeof(IMAGE_IMPORT_DESCRIPTOR), &ours,
              sizeof(ours));

  const auto thunk_value =
      static_cast<typename process::pe_traits<Is32>::thunk>(
          make_rva(layout.hint_offset));
  std::memcpy(bytes + layout.int_offset, &thunk_value, sizeof(thunk_value));
  std::memcpy(bytes + layout.iat_offset, &thunk_value, sizeof(thunk_value));
  std::memcpy(bytes + layout.name_offset, dll_name.data(), dll_name.size());
  std::memcpy(bytes + layout.hint_offset + sizeof(std::uint16_t),
              import_func.data(), import_func.size());

  if (const auto st = process::write(target, bytes, region.get(), layout.total);
      !NT_SUCCESS(st)) {
    LOG_WARN("IAT 区域写入失败：0x{:08X}", static_cast<ULONG>(st));
    return st;
  }

  // 改 NT 头：导入表目录指向新表，清 bound imports 和 checksum。
  detail::page_protection header{handle, module_base,
                                 detail::header_region_size,
                                 PAGE_EXECUTE_READWRITE};
  if (!header.valid()) {
    LOG_WARN("IAT 头页改保护失败：0x{:08X}",
             static_cast<ULONG>(header.status()));
    return header.status();
  }

  nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
      make_rva(0);
  nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
      static_cast<std::uint32_t>((existing_count + 2) *
                                 sizeof(IMAGE_IMPORT_DESCRIPTOR));
  nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]
      .VirtualAddress = 0;
  nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
  nt.OptionalHeader.CheckSum = 0;

  if (const auto st =
          process::write(target, &nt, headers->nt_address, sizeof(nt));
      !NT_SUCCESS(st)) {
    LOG_WARN("IAT 头写入失败：0x{:08X}", static_cast<ULONG>(st));
    return st;
  }

  // 成功路径上尽早把头页保护恢复，别在目标进程里多留可写窗口。
  header.restore();

  void *const region_base = region.get();
  const SIZE_T region_bytes = region.size();

  if (restore_out != nullptr) {
    restore_out->import_va = import_dir.VirtualAddress;
    restore_out->import_size = import_dir.Size;
    restore_out->bound_va = bound_dir.VirtualAddress;
    restore_out->bound_size = bound_dir.Size;
    restore_out->checksum = original_checksum;
    restore_out->region = region_base;
    restore_out->region_size = region_bytes;
    restore_out->is32 = Is32;
  }
  region.detach(); // 区域要留在目标进程里供加载器使用

  LOG_INFO("IAT{} 注入完成：module=0x{:X} new_import_rva=0x{:X} "
           "descriptors={} region=0x{:X}",
           Is32 ? 32 : 64, reinterpret_cast<std::uint64_t>(module_base),
           make_rva(0), existing_count + 1,
           reinterpret_cast<std::uint64_t>(region_base));
  return ntl::status::ok();
}

// --- 还原 -------------------------------------------------------------------
// 先改回头、再释放区域，避免中间态下加载器读到已释放的导入表。
template <bool Is32>
inline ntl::status restore_iat_impl(PEPROCESS target, HANDLE handle,
                                    void *module_base,
                                    const iat_restore_info &info) noexcept {
  if (module_base == nullptr)
    return STATUS_INVALID_PARAMETER;

  auto headers = process::read_headers<Is32>(target, module_base);
  if (!headers)
    return headers.status();

  auto &nt = headers->nt;
  nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
      info.import_va;
  nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
      info.import_size;
  nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]
      .VirtualAddress = info.bound_va;
  nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size =
      info.bound_size;
  nt.OptionalHeader.CheckSum = info.checksum;

  detail::page_protection header{handle, module_base,
                                 detail::header_region_size,
                                 PAGE_EXECUTE_READWRITE};
  if (!header.valid())
    return header.status();

  if (const auto st =
          process::write(target, &nt, headers->nt_address, sizeof(nt));
      !NT_SUCCESS(st))
    return st;

  header.restore();

  if (info.region != nullptr) {
    PVOID region = info.region;
    SIZE_T region_size = 0; // 0 表示整块释放
    (void)ZwFreeVirtualMemory(handle, &region, &region_size, MEM_RELEASE);
  }

  LOG_INFO("IAT{} 已还原：module=0x{:X} import_rva=0x{:X}", Is32 ? 32 : 64,
           reinterpret_cast<std::uint64_t>(module_base), info.import_va);
  return ntl::status::ok();
}

// --- 按目标模块位数分派 -----------------------------------------------------
inline ntl::status inject_iat(PEPROCESS target, HANDLE handle,
                              void *module_base, bool is32,
                              std::string_view dll_name,
                              std::string_view import_func,
                              iat_restore_info *restore_out) noexcept {
  return is32 ? inject_iat_impl<true>(target, handle, module_base, dll_name,
                                      import_func, restore_out)
              : inject_iat_impl<false>(target, handle, module_base, dll_name,
                                       import_func, restore_out);
}

inline ntl::status restore_iat(PEPROCESS target, HANDLE handle,
                               void *module_base,
                               const iat_restore_info &info) noexcept {
  return info.is32
             ? restore_iat_impl<true>(target, handle, module_base, info)
             : restore_iat_impl<false>(target, handle, module_base, info);
}

} // namespace injdrv::inject
