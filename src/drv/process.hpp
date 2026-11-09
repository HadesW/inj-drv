// ============================================================================
// process.hpp
// ----------------------------------------------------------------------------
// 跨进程操作：内存读写、远程虚拟内存分配、PE 解析与模块查找。
// 所有资源都用 RAII 管：进程/线程引用走 ntl::unique_object，句柄走
// ntl::unique_handle，远程内存走 remote_memory，失败路径自动回滚。
//
// IRQL：只能在 PASSIVE_LEVEL 用（涉及 attach、Zw* 与 MmCopyVirtualMemory）。
// ============================================================================

#pragma once

// ntifs.h 而不是 ntddk.h：ZwAllocateVirtualMemory / ZwProtectVirtualMemory /
// PsLookupProcessByProcessId 这些只在 ntifs.h 里声明。
#include <ntifs.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string_view>
#include <utility>

#include <ntimage.h>

#include <ntl/handle>
#include <ntl/result>

#include "../shared/logger.hpp"
#include "match.hpp"

// 这两个 API 由 ntoskrnl 导出但 WDK 头里没有声明，用到就得自己写原型。
extern "C" {
NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess,
                                            PVOID SourceAddress,
                                            PEPROCESS TargetProcess,
                                            PVOID TargetAddress,
                                            SIZE_T BufferSize,
                                            KPROCESSOR_MODE PreviousMode,
                                            PSIZE_T ReturnSize);
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle,
                                               PVOID *BaseAddress,
                                               PSIZE_T RegionSize,
                                               ULONG NewProtect,
                                               PULONG OldProtect);
NTKERNELAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);
NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);
}

namespace injdrv::process {

// --- 常量 -------------------------------------------------------------------
inline constexpr std::uint16_t dos_signature = 0x5A4D;    // 'MZ'
inline constexpr std::uint32_t nt_signature = 0x00004550; // 'PE\0\0'

// --- 附着到目标进程 ---------------------------------------------------------
// KeStackAttachProcess / KeUnstackDetachProcess 必须配对，异常路径也要解开。
class attach {
public:
  explicit attach(PEPROCESS process) noexcept : process_(process) {
    KeStackAttachProcess(process_, &state_);
  }
  ~attach() { KeUnstackDetachProcess(&state_); }

  attach(const attach &) = delete;
  attach &operator=(const attach &) = delete;

private:
  PEPROCESS process_;
  KAPC_STATE state_{};
};

// --- 内存读写 ---------------------------------------------------------------
// 用 __try/__except 直接访问，不 attach、不用 MmCopyVirtualMemory。
// 依据：madCodeHook 驱动（docs/madcodehook）全代码就是这么读目标进程内存的
// （DllList.c 等），没有任何 MmCopyVirtualMemory / KeStackAttachProcess——
// 因为进程/映像通知回调本来就运行在目标进程上下文里。
// MmCopyVirtualMemory 在该上下文返回 STATUS_PARTIAL_COPY，二次 attach 则访问
// 违例，两个坑都踩过。
// __try 不能和需要析构的 C++ 对象同函数，所以拆成裸函数。
inline NTSTATUS raw_copy(void *dst, const void *src, SIZE_T size) noexcept {
  __try {
    std::memcpy(dst, src, size);
    return STATUS_SUCCESS;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return GetExceptionCode();
  }
}

// attach 之后用 __try 直读直写。之前 attach 版访问违例是 PE 结构偏移错
// 导致读了垃圾地址，不是 attach 本身有问题。
inline NTSTATUS read(PEPROCESS target, const void *remote, void *local,
                     SIZE_T size) noexcept {
  attach scope(target);
  return raw_copy(local, remote, size);
}

inline NTSTATUS write(PEPROCESS target, const void *local, void *remote,
                      SIZE_T size) noexcept {
  attach scope(target);
  return raw_copy(remote, local, size);
}

template <class T>
NTSTATUS read_at(PEPROCESS target, const void *remote, T &out) noexcept {
  return read(target, remote, &out, sizeof(T));
}

// --- 进程 / 线程引用 --------------------------------------------------------
using process_ref = ntl::unique_object<PEPROCESS>;
using thread_ref = ntl::unique_object<PETHREAD>;

[[nodiscard]] inline ntl::result<process_ref>
reference_process(HANDLE pid) noexcept {
  PEPROCESS object = nullptr;
  if (const auto st = PsLookupProcessByProcessId(pid, &object); !NT_SUCCESS(st))
    return ntl::unexpected(st);
  return process_ref{object};
}

[[nodiscard]] inline ntl::result<thread_ref>
reference_thread(HANDLE tid) noexcept {
  PETHREAD object = nullptr;
  if (const auto st = PsLookupThreadByThreadId(tid, &object); !NT_SUCCESS(st))
    return ntl::unexpected(st);
  return thread_ref{object};
}

// 进程对象引用 + 全权限内核句柄。两者都随结构体析构自动释放。
struct process_handle {
  process_ref object;
  ntl::unique_handle handle;

  PEPROCESS process() const noexcept { return object.get(); }
  HANDLE native_handle() const noexcept { return handle.get(); }
  explicit operator bool() const noexcept {
    return object.valid() && handle.valid();
  }
};

[[nodiscard]] inline ntl::result<process_handle>
open_process(HANDLE pid) noexcept {
  auto object = reference_process(pid);
  if (!object)
    return ntl::unexpected(object.status());

  ntl::unique_handle handle;
  if (const auto st = ObOpenObjectByPointer(
          object->get(), OBJ_KERNEL_HANDLE, nullptr, PROCESS_ALL_ACCESS,
          *PsProcessType, KernelMode, handle.put());
      !NT_SUCCESS(st))
    return ntl::unexpected(st);

  return process_handle{std::move(*object), std::move(handle)};
}

// --- 目标进程位数 -----------------------------------------------------------
// Wow64 进程有独立的 32 位 PEB；非 Wow64 进程返回 nullptr。
inline bool is_wow64(PEPROCESS target) noexcept {
  return PsGetProcessWow64Process(target) != nullptr;
}

// --- 远程 RWX 内存块 --------------------------------------------------------
// 析构时自动释放，注入中途失败不会在目标进程里留下垃圾。
class remote_memory {
public:
  remote_memory() = default;
  remote_memory(const remote_memory &) = delete;
  remote_memory &operator=(const remote_memory &) = delete;

  remote_memory(remote_memory &&other) noexcept { swap(other); }
  remote_memory &operator=(remote_memory &&other) noexcept {
    remote_memory temp{std::move(other)};
    swap(temp);
    return *this;
  }

  ~remote_memory() { reset(); }

  // 用进程句柄而不是 attach + ZwCurrentProcess()：madCodeHook 就是这么做的
  // （open_target 拿 HANDLE，ZwAllocateVirtualMemory 直接传它）。attach 在
  // 通知回调上下文里会死锁，句柄方式不会。
  // preferred 非空时按指定基址分配：32 位目标的桩必须落在 4GB 以下，地址被
  // 占用时返回 STATUS_CONFLICTING_ADDRESSES，由调用方换下一个候选。
  static ntl::result<remote_memory>
  allocate(HANDLE handle, SIZE_T size, void *preferred = nullptr,
           ULONG protect = PAGE_EXECUTE_READWRITE) noexcept {
    PVOID base = preferred;
    SIZE_T region = size;
    if (const auto st = ZwAllocateVirtualMemory(
            handle, &base, 0, &region, MEM_COMMIT | MEM_RESERVE, protect);
        !NT_SUCCESS(st))
      return ntl::unexpected(st);

    remote_memory block;
    block.handle_ = handle;
    block.base_ = base;
    block.size_ = region;
    return block;
  }

  // 改页保护，同样用句柄。
  NTSTATUS protect(ULONG new_protect, ULONG *old_protect) noexcept {
    SIZE_T region = size_;
    PVOID base = base_;
    return ZwProtectVirtualMemory(handle_, &base, &region, new_protect,
                                  old_protect);
  }

  // 放弃所有权但不释放。桩写完打完补丁后必须调用——那块内存要一直留在
  // 目标进程里给桩执行，析构释放掉的话入口点跳过去就是空内存。
  void detach() noexcept {
    handle_ = nullptr;
    base_ = nullptr;
    size_ = 0;
  }

  void reset() noexcept {
    if (base_ == nullptr)
      return;

    PVOID base = base_;
    SIZE_T region = 0; // 0 表示整块释放
    ZwFreeVirtualMemory(handle_, &base, &region, MEM_RELEASE);
    detach();
  }

  void swap(remote_memory &other) noexcept {
    std::swap(handle_, other.handle_);
    std::swap(base_, other.base_);
    std::swap(size_, other.size_);
  }

  void *get() const noexcept { return base_; }
  SIZE_T size() const noexcept { return size_; }

private:
  HANDLE handle_ = nullptr;
  void *base_ = nullptr;
  SIZE_T size_ = 0;
};

inline void swap(remote_memory &lhs, remote_memory &rhs) noexcept {
  lhs.swap(rhs);
}

// 在 4GB 以下找一块可用区域：从 preferred 起按 64K 步进，只有地址冲突才继续。
// 32 位目标的桩/导入表必须落在低 4GB，32 位代码才够得着。
inline ntl::result<remote_memory>
allocate_below_4g(HANDLE handle, std::uintptr_t preferred, SIZE_T size) noexcept {
  for (std::uintptr_t offset = 0; offset <= 0x4000000; offset += 0x10000) {
    const std::uintptr_t candidate = preferred + offset;
    if (candidate + size > 0xFFFFFFFFull)
      break;
    auto block = remote_memory::allocate(handle, size,
                                         reinterpret_cast<void *>(candidate));
    if (block)
      return block;
    if (static_cast<NTSTATUS>(block.status()) != STATUS_CONFLICTING_ADDRESSES)
      return block;
  }
  return ntl::unexpected(STATUS_CONFLICTING_ADDRESSES);
}

// --- PE 头 ------------------------------------------------------------------
// 32/64 位模块的差异集中在这里，其余解析逻辑只写一遍。
template <bool Is32> struct pe_traits;
template <> struct pe_traits<false> {
  using nt_headers = IMAGE_NT_HEADERS64;
  using thunk = std::uint64_t;
  static constexpr std::uint16_t optional_magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
};
template <> struct pe_traits<true> {
  using nt_headers = IMAGE_NT_HEADERS32;
  using thunk = std::uint32_t;
  static constexpr std::uint16_t optional_magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
};

template <bool Is32> struct image_headers {
  IMAGE_DOS_HEADER dos{};
  typename pe_traits<Is32>::nt_headers nt{};
  std::uint8_t *nt_address = nullptr;
};

template <bool Is32>
[[nodiscard]] inline ntl::result<image_headers<Is32>>
read_headers(PEPROCESS target, const void *module_base) noexcept {
  if (module_base == nullptr)
    return ntl::unexpected(STATUS_INVALID_PARAMETER);

  const auto *base = static_cast<const std::uint8_t *>(module_base);
  image_headers<Is32> headers;
  if (const auto st = read_at(target, base, headers.dos); !NT_SUCCESS(st))
    return ntl::unexpected(st);
  if (headers.dos.e_magic != IMAGE_DOS_SIGNATURE)
    return ntl::unexpected(STATUS_INVALID_IMAGE_FORMAT);

  headers.nt_address = const_cast<std::uint8_t *>(base) + headers.dos.e_lfanew;
  if (const auto st = read_at(target, headers.nt_address, headers.nt);
      !NT_SUCCESS(st))
    return ntl::unexpected(st);
  if (headers.nt.Signature != IMAGE_NT_SIGNATURE ||
      headers.nt.OptionalHeader.Magic != pe_traits<Is32>::optional_magic)
    return ntl::unexpected(STATUS_INVALID_IMAGE_FORMAT);

  return headers;
}

// --- 导出解析 ---------------------------------------------------------------
// PE 结构一律用 WDK 的 <ntimage.h>。之前手搓过一份偏移，image_base 算到了
// 文件偏移 40 而实际是 56，data_directory 全错位，拿垃圾 RVA 去读就访问违例。
template <bool Is32>
[[nodiscard]] inline ntl::result<void *>
find_export(PEPROCESS target, const void *module_base,
            std::string_view wanted) noexcept {
  if (wanted.empty() || wanted.size() >= 64)
    return ntl::unexpected(STATUS_INVALID_PARAMETER);

  auto headers = read_headers<Is32>(target, module_base);
  if (!headers)
    return ntl::unexpected(headers.status());

  const auto &dir =
      headers->nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (dir.VirtualAddress == 0 || dir.Size == 0)
    return ntl::unexpected(STATUS_PROCEDURE_NOT_FOUND);

  const auto *base = static_cast<const std::uint8_t *>(module_base);
  IMAGE_EXPORT_DIRECTORY exports{};
  if (const auto st = read_at(target, base + dir.VirtualAddress, exports);
      !NT_SUCCESS(st))
    return ntl::unexpected(st);

  const auto *names = base + exports.AddressOfNames;
  const auto *ordinals = base + exports.AddressOfNameOrdinals;
  const auto *functions = base + exports.AddressOfFunctions;

  for (std::uint32_t i = 0; i < exports.NumberOfNames; ++i) {
    std::uint32_t name_rva = 0;
    if (const auto st = read_at(target, names + i * 4, name_rva);
        !NT_SUCCESS(st))
      return ntl::unexpected(st);

    std::array<char, 64> candidate{};
    if (const auto st = read(target, base + name_rva, candidate.data(),
                             candidate.size() - 1);
        !NT_SUCCESS(st))
      return ntl::unexpected(st);

    if (std::string_view{candidate.data()} != wanted)
      continue;

    std::uint16_t ordinal = 0;
    if (const auto st = read_at(target, ordinals + i * 2, ordinal);
        !NT_SUCCESS(st))
      return ntl::unexpected(st);

    std::uint32_t func_rva = 0;
    if (const auto st = read_at(target, functions + ordinal * 4, func_rva);
        !NT_SUCCESS(st))
      return ntl::unexpected(st);

    return static_cast<void *>(const_cast<std::uint8_t *>(base + func_rva));
  }

  return ntl::unexpected(STATUS_PROCEDURE_NOT_FOUND);
}

// 取模块入口点的绝对地址（module_base + AddressOfEntryPoint）。
template <bool Is32>
[[nodiscard]] inline ntl::result<void *>
find_entry_point(PEPROCESS target, const void *module_base) noexcept {
  auto headers = read_headers<Is32>(target, module_base);
  if (!headers)
    return ntl::unexpected(headers.status());

  const auto rva = headers->nt.OptionalHeader.AddressOfEntryPoint;
  if (rva == 0)
    return ntl::unexpected(STATUS_NOT_FOUND);

  return static_cast<void *>(
      const_cast<std::uint8_t *>(static_cast<const std::uint8_t *>(module_base)) +
      rva);
}

// --- 模块基址（PEB/LDR 遍历）------------------------------------------------
// 老实现就是这么拿 ntdll 基址的，比 IMAGE_INFO.ImageBase 可靠。
// x64：PEB+0x18=Ldr，Ldr+0x20=InMemoryOrder 表头，链表项 = 结点-0x10，
//      DllBase 在 +0x30，BaseDllName 在 +0x58。
// x86：PEB+0x0C=Ldr，Ldr+0x14=InMemoryOrder 表头，链表项 = 结点-0x08，
//      DllBase 在 +0x18，BaseDllName（UNICODE_STRING32）在 +0x2C。
template <bool Is32> struct ldr_layout;
template <> struct ldr_layout<false> {
  using value_type = std::uint64_t;
  static constexpr std::size_t peb_ldr = 0x18;
  static constexpr std::size_t list_head = 0x20;
  static constexpr std::size_t node_bias = 0x10;
  static constexpr std::size_t dll_base = 0x30;
  static constexpr std::size_t dll_name = 0x58;
  static constexpr std::size_t name_buffer = 8;
};
template <> struct ldr_layout<true> {
  using value_type = std::uint32_t;
  static constexpr std::size_t peb_ldr = 0x0C;
  static constexpr std::size_t list_head = 0x14;
  static constexpr std::size_t node_bias = 0x08;
  static constexpr std::size_t dll_base = 0x18;
  static constexpr std::size_t dll_name = 0x2C;
  static constexpr std::size_t name_buffer = 4;
};

template <bool Is32>
[[nodiscard]] inline ntl::result<void *>
find_module(PEPROCESS target, std::wstring_view wanted) noexcept {
  using layout = ldr_layout<Is32>;
  using value_type = typename layout::value_type;

  const auto addr = [](value_type value) noexcept {
    return reinterpret_cast<const void *>(static_cast<std::uintptr_t>(value));
  };

  const auto *peb = [&]() -> const std::uint8_t * {
    if constexpr (Is32)
      return static_cast<const std::uint8_t *>(PsGetProcessWow64Process(target));
    else
      return static_cast<const std::uint8_t *>(PsGetProcessPeb(target));
  }();
  if (peb == nullptr)
    return ntl::unexpected(STATUS_NOT_FOUND);

  value_type ldr = 0;
  if (const auto st = read_at(target, peb + layout::peb_ldr, ldr);
      !NT_SUCCESS(st))
    return ntl::unexpected(st);
  if (ldr == 0)
    return ntl::unexpected(STATUS_NOT_FOUND);

  const value_type head = ldr + layout::list_head;
  value_type node = 0;
  if (const auto st = read_at(target, addr(head), node); !NT_SUCCESS(st))
    return ntl::unexpected(st);

  for (int i = 0; i < 256 && node != 0 && node != head; ++i) {
    const value_type entry = node - layout::node_bias;

    value_type dll_base = 0;
    if (const auto st = read_at(target, addr(entry + layout::dll_base),
                                dll_base);
        !NT_SUCCESS(st))
      return ntl::unexpected(st);

    // BaseDllName 是 UNICODE_STRING{USHORT Length; USHORT MaxLength; ...}
    std::uint16_t length = 0;
    if (const auto st = read_at(target, addr(entry + layout::dll_name), length);
        !NT_SUCCESS(st))
      return ntl::unexpected(st);

    value_type buffer = 0;
    if (const auto st = read_at(
            target, addr(entry + layout::dll_name + layout::name_buffer),
            buffer);
        !NT_SUCCESS(st))
      return ntl::unexpected(st);

    std::array<wchar_t, 64> name{};
    const std::size_t chars =
        (std::min)(static_cast<std::size_t>(length / sizeof(wchar_t)),
                   name.size() - 1);
    if (chars > 0) {
      if (const auto st =
              read(target, addr(buffer), name.data(), chars * sizeof(wchar_t));
          !NT_SUCCESS(st))
        return ntl::unexpected(st);
    }

    if (match::equals_ci(std::wstring_view{name.data(), chars}, wanted))
      return reinterpret_cast<void *>(static_cast<std::uintptr_t>(dll_base));

    if (const auto st = read_at(target, addr(node), node); !NT_SUCCESS(st))
      return ntl::unexpected(st);
  }

  return ntl::unexpected(STATUS_NOT_FOUND);
}

} // namespace injdrv::process
