// ============================================================================
// notify.hpp
// ----------------------------------------------------------------------------
// 进程/映像/线程通知回调。
//
//   process_cb  建跟踪槽、进程退出时清槽
//   image_cb    填 exe 与 ntdll 基址、触发注入
//   thread_cb   记目标线程（APC 用），必要时触发 APC 注入
//
// 为什么不用 PsSetCreateProcessNotifyRoutineEx：那个 API 要求驱动映像带
// IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY（/INTEGRITYCHECK），否则返回
// STATUS_ACCESS_DENIED。旧版 PsSetCreateProcessNotifyRoutine 无此要求，
// exe 名改从 image_notify 的 FullImageName 取——一个进程加载的第一个映像
// 就是它的主模块。
//
// 约定：回调运行在 PASSIVE_LEVEL，且处在加载器的深调用链上，内核栈余量很小。
// 回调里只做记账和投递任务：不写日志、不做跨进程 IO、不在栈上放大缓冲。
// 真正的注入一律交给系统线程/工作项。
// ============================================================================

#pragma once

#include <ntifs.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

#include <ntl/pool_allocator>
// crtsys 的 system_thread 自带一版 ZwWaitForSingleObject 声明，与 WDK 28000
// ntifs.h 的声明签名一致但链接属性不同，会触发 C4273（项目开了 /WX）。
#pragma warning(push)
#pragma warning(disable : 4273)
#include <ntl/system_thread>
#pragma warning(pop)
#include <ntl/work_item>

#include "globals.hpp"
#include "../shared/logger.hpp"
#include "match.hpp"
#include "process.hpp"
#include "target.hpp"
#include "inject/apc.hpp"
#include "inject/iat.hpp"
#include "inject/jmp.hpp"

namespace injdrv::notify {

// 跟踪目标上限。超过就丢新进程并记警告，避免无上限增长吃光非分页内存。
inline constexpr std::size_t max_tracked_targets = 4096;

namespace detail {

enum class method : std::uint8_t { jmp, apc };

// 掩码匹配：命中任一规则即算该进程需要注入。
inline bool matches_any_rule(std::wstring_view exe_name) noexcept {
  auto &state = xglobal::device->extension();
  for (const auto &rule : state.rules) {
    if (match::should_inject(exe_name, rule.include_mask, rule.exclude_mask))
      return true;
  }
  return false;
}

inline target::record *find_target(std::uint64_t pid) noexcept {
  auto &state = xglobal::device->extension();
  for (auto &rec : state.targets) {
    if (rec.pid == pid)
      return &rec;
  }
  return nullptr;
}

// 进程通知缺失时的兜底：直接查目标是不是 Wow64。
inline bool is_wow64_process(HANDLE pid) noexcept {
  const auto process = process::reference_process(pid);
  return process && process::is_wow64(process->get());
}

// 从 UNICODE_STRING 拷出定长缓冲，末尾补终止符。
inline std::wstring_view copy_name(wchar_t *dst, std::size_t cap,
                                   PUNICODE_STRING src) noexcept {
  if (src == nullptr || src->Buffer == nullptr || src->Length == 0)
    return {};

  const std::size_t n =
      (std::min)(static_cast<std::size_t>(src->Length / sizeof(wchar_t)),
                 cap - 1);
  std::copy_n(src->Buffer, n, dst);
  dst[n] = L'\0';
  return dst;
}

// 逐条命中规则的方法选择（调用方持 state.lock）。
// IAT 规则在 exe 映像事件里单独处理，这里只看其余规则。
// JMP 优先：只要有默认规则就走 JMP，APC 规则的 DLL 也由同一个 JMP 桩装载；
// 只有命中的规则全部标了 APC 才投递 APC。
inline bool select_method(const target::record &rec,
                          const xglobal::device_state &state,
                          method &kind) noexcept {
  bool has_jmp = false;
  bool has_apc = false;
  for (const auto &rule : state.rules) {
    if (!match::should_inject(target::name_of(rec), rule.include_mask,
                              rule.exclude_mask))
      continue;
    if ((rule.flags & protocol::inject_via_iat_patching) != 0)
      continue;
    if ((rule.flags & protocol::inject_via_apc) != 0)
      has_apc = true;
    else
      has_jmp = true;
  }

  if (has_jmp) {
    kind = method::jmp;
    return true;
  }
  if (has_apc) {
    kind = method::apc;
    return true;
  }
  return false;
}

} // namespace detail

// --- 注入任务 ---------------------------------------------------------------
// 路径直接放在池上的 job 里：16 条 × 260 wchar 有 8KB 多，绝不能放通知回调栈。
struct inject_job {
  std::uint64_t pid = 0;
  std::uint64_t exe_base = 0;
  std::uint64_t ntdll_base = 0;
  std::uint64_t thread_id = 0; // 仅 APC 使用
  std::uint32_t path_count = 0;
  bool is32 = false;
  detail::method kind = detail::method::jmp;
  wchar_t exe_name[target::max_name_chars]{};
  wchar_t paths[shellcode::max_dlls][protocol::max_path_chars]{};
};

using job_ptr = ntl::pool_ptr<inject_job>;

namespace detail {

inline void run_inject_job(inject_job &job) noexcept {
  auto proc = process::open_process(reinterpret_cast<HANDLE>(job.pid));
  if (!proc) {
    LOG_WARN("查进程对象/打开句柄失败 pid=0x{:X} 0x{:08X}", job.pid,
             static_cast<ULONG>(static_cast<NTSTATUS>(proc.status())));
    return;
  }

  // ntdll 基址优先用映像通知给的 ImageBase（madCodeHook 的做法）。
  // 映像通知早于加载器把模块挂进 InMemoryOrder 链表，通知上下文里走
  // PEB32/LDR 会返回 STATUS_NOT_FOUND；PEB 遍历只作兜底。
  void *ntdll = reinterpret_cast<void *>(job.ntdll_base);
  const bool from_peb = ntdll == nullptr;
  if (from_peb) {
    const auto found =
        job.is32 ? process::find_module<true>(proc->process(), L"ntdll.dll")
                 : process::find_module<false>(proc->process(), L"ntdll.dll");
    if (!found) {
      LOG_WARN("找不到 ntdll pid=0x{:X} 0x{:08X}", job.pid,
               static_cast<ULONG>(static_cast<NTSTATUS>(found.status())));
      return;
    }
    ntdll = *found;
  }

  LOG_INFO("ntdll 基址（{}）pid=0x{:X} exe={} bits={} base=0x{:X} 方法={} "
           "dlls={}",
           from_peb ? "PEB" : "映像通知", job.pid, log::narrow(job.exe_name),
           job.is32 ? 32 : 64, reinterpret_cast<std::uint64_t>(ntdll),
           job.kind == method::apc ? "APC" : "JMP", job.path_count);

  std::array<std::wstring_view, shellcode::max_dlls> paths{};
  for (std::uint32_t i = 0; i < job.path_count && i < shellcode::max_dlls; ++i)
    paths[i] = job.paths[i];
  const std::span<const std::wstring_view> batch(paths.data(),
                                                 job.path_count);

  const auto ntdll_base = reinterpret_cast<std::uint64_t>(ntdll);

  if (job.kind == method::apc) {
    auto thread =
        process::reference_thread(reinterpret_cast<HANDLE>(job.thread_id));
    if (!thread) {
      LOG_WARN("APC：找不到目标线程 tid=0x{:X} 0x{:08X}", job.thread_id,
               static_cast<ULONG>(static_cast<NTSTATUS>(thread.status())));
      return;
    }

    const auto status =
        job.is32 ? inject::inject_apc32(proc->process(),
                                        proc->native_handle(), ntdll_base,
                                        thread->get(), batch)
                 : inject::inject_apc64(proc->process(),
                                        proc->native_handle(), ntdll_base,
                                        thread->get(), batch);
    if (status.is_ok()) {
      LOG_INFO("注入完成 pid=0x{:X} exe={} 方法=APC dlls={}", job.pid,
               log::narrow(job.exe_name), job.path_count);
    } else {
      LOG_WARN("注入失败 pid=0x{:X} 0x{:08X}", job.pid,
               static_cast<ULONG>(static_cast<NTSTATUS>(status)));
    }
    return;
  }

  const auto status =
      job.is32 ? inject::inject_jmp32(proc->process(), proc->native_handle(),
                                      job.exe_base, ntdll_base, batch)
               : inject::inject_jmp64(proc->process(), proc->native_handle(),
                                      job.exe_base, ntdll_base, batch);
  if (status.is_ok()) {
    LOG_INFO("注入完成 pid=0x{:X} exe={} 方法=JMP dlls={}", job.pid,
             log::narrow(job.exe_name), job.path_count);
  } else {
    LOG_WARN("注入失败 pid=0x{:X} 0x{:08X}", job.pid,
             static_cast<ULONG>(static_cast<NTSTATUS>(status)));
  }
}

} // namespace detail

inline void inject_thread(PVOID context) noexcept {
  {
    // 线程退出不会展开 C++ 栈，必须在本作用域内释放 job 再终止线程。
    job_ptr job{static_cast<inject_job *>(context),
                ntl::pool_deleter<inject_job>{"inJj"}};
    if (job)
      detail::run_inject_job(*job);
  }
  PsTerminateSystemThread(STATUS_SUCCESS);
}

// 在锁内准备任务：收集全部命中的非 IAT 规则，成功时把目标标记为已注入。
// 返回空指针表示没有可投递的 DLL（参数错误或内存不足）。
inline job_ptr prepare_job(target::record &rec,
                           const xglobal::device_state &state,
                           detail::method kind,
                           std::uint64_t thread_id) noexcept {
  auto created = ntl::try_make_pool<inject_job>("inJj");
  if (!created) {
    LOG_WARN("注入任务分配失败 pid=0x{:X}", rec.pid);
    return {};
  }
  auto job = std::move(*created);
  job->pid = rec.pid;
  job->exe_base = rec.exe_base;
  job->ntdll_base = rec.is32 ? rec.ntdll32_base : rec.ntdll_base;
  job->thread_id = thread_id;
  job->is32 = rec.is32;
  job->kind = kind;
  std::copy_n(rec.exe_name.begin(), target::max_name_chars, job->exe_name);

  for (const auto &rule : state.rules) {
    if (job->path_count >= shellcode::max_dlls)
      break;
    if (!match::should_inject(target::name_of(rec), rule.include_mask,
                              rule.exclude_mask))
      continue;
    if ((rule.flags & protocol::inject_via_iat_patching) != 0)
      continue;
    std::copy_n(rule.name, protocol::max_path_chars,
                job->paths[job->path_count++]);
  }

  if (job->path_count == 0)
    return {};

  rec.injected = true;
  return job;
}

inline void launch_job(job_ptr job) noexcept {
  if (!job)
    return;

  const auto pid = job->pid;
  auto thread = ntl::system_thread::create(inject_thread, job.get());
  if (!thread) {
    LOG_WARN("注入线程创建失败 pid=0x{:X} 0x{:08X}", pid,
             static_cast<ULONG>(static_cast<NTSTATUS>(thread.status())));

    // 允许后续事件重试这次注入。job 随作用域结束自动回收。
    auto &state = xglobal::device->extension();
    std::scoped_lock guard(state.lock);
    if (auto *rec = detail::find_target(pid); rec != nullptr)
      rec->injected = false;
    return;
  }

  (void)job.release(); // 线程入口用 pool_ptr 接管
}

// IAT 必须在 exe 的映像通知返回前完成：此刻加载器还没解析这个模块的导入表，
// 改完 NT 头返回后它就会按新表装载我们的 DLL。真正干活的地方是工作项
// （见下面 inject_iat_waited），这里只做参数准备。
//
// DLL 名字只用基名，走加载器的标准搜索路径（测试时把载荷放进 System32）。
// 成功时把原始头字段写进 restore_out，供后面的 restore 命令还原。
inline ntl::status inject_iat_now(std::uint64_t pid, std::uint64_t exe_base,
                                  bool is32, const wchar_t *exe_name,
                                  const wchar_t *dll_path,
                                  inject::iat_restore_info &restore_out) noexcept {
  if (dll_path == nullptr || *dll_path == L'\0')
    return ntl::status{STATUS_INVALID_PARAMETER};

  const auto leaf = match::file_base(dll_path);
  char ansi[protocol::max_path_chars]{};
  for (std::size_t i = 0; i < leaf.size() && i < sizeof(ansi) - 1; ++i)
    ansi[i] = leaf[i] < 0x80 ? static_cast<char>(leaf[i]) : '?';

  auto proc = process::open_process(reinterpret_cast<HANDLE>(pid));
  if (!proc) {
    LOG_WARN("IAT：查进程对象/打开句柄失败 pid=0x{:X} exe={} 0x{:08X}", pid,
             log::narrow(exe_name),
             static_cast<ULONG>(static_cast<NTSTATUS>(proc.status())));
    return proc.status();
  }

  LOG_INFO("IAT 注入开始 pid=0x{:X} exe={} bits={} exe_base=0x{:X} dll={}",
           pid, log::narrow(exe_name), is32 ? 32 : 64, exe_base,
           log::narrow(leaf));
  const auto status = inject::inject_iat(
      proc->process(), proc->native_handle(),
      reinterpret_cast<void *>(exe_base), is32, ansi, "injdrv_autoload",
      &restore_out);

  if (status.is_ok()) {
    LOG_INFO("IAT 注入完成 pid=0x{:X} exe={}", pid, log::narrow(exe_name));
  } else {
    LOG_WARN("IAT 注入失败 pid=0x{:X} exe={} 0x{:08X}", pid,
             log::narrow(exe_name),
             static_cast<ULONG>(static_cast<NTSTATUS>(status)));
  }
  return status;
}

// --- IAT 注入的工作项 -------------------------------------------------------
// 补丁必须在映像通知返回前完成，但绝不能在通知回调自己的栈上做：回调躺在
// 加载器深调用链上，栈余量很小，注入里的池分配/跨进程读写/写日志曾把内核栈
// 压穿（0x7F/8 双重故障）。
//
// madCodeHook 的做法（DriverEvents.c:521-557）是投递工作项，Win8+ 上再
// KeWaitForSingleObject 等它完成——镜像还没开始解析导入表，语义仍是同步的，
// 但实际工作跑在系统工作线程的新栈上。
struct iat_work {
  std::uint64_t pid = 0;
  std::uint64_t exe_base = 0;
  bool is32 = false;
  wchar_t exe_name[target::max_name_chars]{};
  wchar_t dll_path[protocol::max_path_chars]{};
  inject::iat_restore_info restore{};
  ntl::status result = ntl::status{STATUS_UNSUCCESSFUL};
};

inline bool inject_iat_waited(std::uint64_t pid, std::uint64_t exe_base,
                              bool is32, const wchar_t *exe_name,
                              const wchar_t *dll_path,
                              inject::iat_restore_info &restore_out) noexcept {
  auto created = ntl::try_make_pool<iat_work>("inJi");
  if (!created) {
    LOG_WARN("IAT 工作项分配失败 pid=0x{:X}", pid);
    return false;
  }
  auto job = std::move(*created);
  job->pid = pid;
  job->exe_base = exe_base;
  job->is32 = is32;
  std::copy_n(exe_name, target::max_name_chars, job->exe_name);
  std::copy_n(dll_path, protocol::max_path_chars, job->dll_path);

  ntl::passive_work_item work([&job]() noexcept {
    job->result = inject_iat_now(job->pid, job->exe_base, job->is32,
                                 job->exe_name, job->dll_path, job->restore);
  });

  if (const auto queued = work.queue(); !queued.is_ok()) {
    LOG_WARN("IAT 工作项投递失败 pid=0x{:X} 0x{:08X}", pid,
             static_cast<ULONG>(static_cast<NTSTATUS>(queued)));
    return false;
  }
  (void)work.wait();

  restore_out = job->restore;
  return job->result.is_ok();
}

// --- 映像加载：建槽 + 记基址 + 触发注入 --------------------------------------
inline void on_image(PUNICODE_STRING full_name, HANDLE pid_handle,
                     PIMAGE_INFO info) noexcept {
  if (info == nullptr || info->ImageBase == nullptr)
    return;

  const auto pid = reinterpret_cast<std::uint64_t>(pid_handle);
  const auto base = reinterpret_cast<std::uint64_t>(info->ImageBase);

  wchar_t scratch[target::max_name_chars]{};
  const auto path =
      detail::copy_name(scratch, target::max_name_chars, full_name);
  const auto name = match::file_base(path);
  // 注意：这里不能打日志。映像通知运行在加载器的深调用链上，内核栈余量
  // 很小；std::format + 同步写文件曾把栈压穿导致 0x7F/8 双重故障。
  // 回调里只做记账和投递，日志留给工作项/注入线程。
  if (name.empty())
    return;

  // 锁内只做记账，注入参数拷出来后解锁。
  wchar_t iat_dll_path[protocol::max_path_chars]{};
  wchar_t iat_exe_name[target::max_name_chars]{};
  job_ptr job;
  bool rec_is32 = false;
  bool iat_fire = false;

  {
    auto &state = xglobal::device->extension();
    std::scoped_lock guard(state.lock);

    target::record *rec = detail::find_target(pid);
    if (rec == nullptr) {
      // 该进程的第一个映像就是主模块。进程通知可能晚到或缺失，这里补建槽。
      if (state.targets.size() >= max_tracked_targets) {
        LOG_WARN("跟踪槽已满，丢弃 pid=0x{:X} {}", pid, log::narrow(name));
        return;
      }

      target::record fresh;
      fresh.pid = pid;
      target::set_name(fresh, path);
      fresh.matched = detail::matches_any_rule(name);
      fresh.exe_base = base;
      fresh.is32 = detail::is_wow64_process(pid_handle);

      try {
        state.targets.push_back(fresh);
      } catch (...) {
        LOG_WARN("跟踪槽分配失败，丢弃 pid=0x{:X}", pid);
        return;
      }
      return;
    }

    const bool is_ntdll = match::equals_ci(name, L"ntdll.dll");
    const bool is_exe = match::equals_ci(name, target::name_of(*rec));
    const bool low_image = base < 0x100000000ull;

    if (is_ntdll) {
      // 基址低于 4GB 视为 32 位映像（Wow64 目标里的 32 位 ntdll）。
      if (low_image) {
        rec->ntdll32_base = base;
      } else {
        rec->ntdll_base = base;
      }
    } else if (is_exe) {
      rec->exe_base = base;

      // IAT 方式在 exe 映像事件里同步打补丁——导入表还没被加载器解析。
      if (rec->matched && !rec->injected) {
        for (const auto &rule : state.rules) {
          if (!match::should_inject(target::name_of(*rec), rule.include_mask,
                                    rule.exclude_mask))
            continue;
          if ((rule.flags & protocol::inject_via_iat_patching) != 0) {
            std::copy_n(rule.name, protocol::max_path_chars, iat_dll_path);
            std::copy_n(rec->exe_name.begin(), target::max_name_chars,
                        iat_exe_name);
            rec->injected = true;
            rec_is32 = rec->is32;
            iat_fire = true;
          }
          break;
        }
      }
    }

    // exe 与 ntdll 基址都就绪后投递 JMP / APC。
    // 与 madCodeHook DriverEvents.c:439-464 一致：ntdll 基址直接取通知
    // 参数里的 ImageBase，不走 PEB 遍历。映像通知发生在加载器链接模块
    // 之前，那一刻 InMemoryOrder 链表里还没有 ntdll（32 位目标实测
    // find_module32 返回 STATUS_NOT_FOUND）。Wow64 目标等 32 位 ntdll
    // 事件（基址 < 4GB），x64 目标等 64 位 ntdll 事件。
    const std::uint64_t ntdll_base =
        rec->is32 ? rec->ntdll32_base : rec->ntdll_base;
    if (rec->matched && !rec->injected && rec->exe_base != 0 &&
        ntdll_base != 0) {
      detail::method kind;
      if (detail::select_method(*rec, state, kind)) {
        if (kind == detail::method::jmp) {
          job = prepare_job(*rec, state, kind, 0);
        } else if (rec->apc_thread_id != 0) {
          job = prepare_job(*rec, state, kind, rec->apc_thread_id);
        }
        // APC 还没有可用线程时，等 on_thread 记下线程后再投递。
      }
    }
  }

  if (iat_fire) {
    inject::iat_restore_info restore{};
    if (inject_iat_waited(pid, base, rec_is32, iat_exe_name, iat_dll_path,
                          restore)) {
      // 还原信息回填到跟踪槽。进程可能已经退出（槽被删），那就没得还原了。
      auto &state = xglobal::device->extension();
      std::scoped_lock guard(state.lock);
      if (auto *rec = detail::find_target(pid); rec != nullptr) {
        rec->iat = restore;
        rec->iat_active = true;
      }
    }
    return;
  }

  launch_job(std::move(job));
}

// --- 线程创建/退出：记 APC 线程、必要时投递 --------------------------------
// 线程通知同样在进程创建的深调用链上，只做记账；APC 由系统线程投递。
inline void on_thread(HANDLE pid_handle, HANDLE tid_handle,
                      BOOLEAN create) noexcept {
  const auto pid = reinterpret_cast<std::uint64_t>(pid_handle);
  const auto tid = reinterpret_cast<std::uint64_t>(tid_handle);
  job_ptr job;

  auto &state = xglobal::device->extension();
  {
    std::scoped_lock guard(state.lock);

    auto *rec = detail::find_target(pid);
    if (rec == nullptr || !rec->matched)
      return;

    if (!create) {
      // 记下的线程先退出了：清掉，等后续线程补位（还没注入时）。
      if (rec->apc_thread_id == tid)
        rec->apc_thread_id = 0;
      return;
    }

    if (rec->apc_thread_id == 0)
      rec->apc_thread_id = tid;

    const std::uint64_t ntdll_base =
        rec->is32 ? rec->ntdll32_base : rec->ntdll_base;
    detail::method kind;
    if (!rec->injected && rec->exe_base != 0 && ntdll_base != 0 &&
        detail::select_method(*rec, state, kind) &&
        kind == detail::method::apc) {
      // 用刚创建的线程：初始线程通常最先进消息循环/可告警等待。
      rec->apc_thread_id = tid;
      job = prepare_job(*rec, state, kind, tid);
    }
  }

  launch_job(std::move(job));
}

// --- 进程创建/退出：只建槽、清槽 ---------------------------------------------
// 进程通知同样在深调用链上，只做记账；注入全部由映像/线程通知投递。
inline void on_process(HANDLE pid_handle, BOOLEAN create) noexcept {
  const auto pid = reinterpret_cast<std::uint64_t>(pid_handle);
  auto &state = xglobal::device->extension();

  if (!create) {
    std::scoped_lock guard(state.lock);
    for (auto it = state.targets.begin(); it != state.targets.end(); ++it) {
      if (it->pid == pid) {
        state.targets.erase(it);
        return;
      }
    }
    return;
  }

  const auto process = process::reference_process(pid_handle);
  if (!process) {
    LOG_WARN("查进程对象失败 pid=0x{:X} 0x{:08X}", pid,
             static_cast<ULONG>(static_cast<NTSTATUS>(process.status())));
    return;
  }

  // exe 名：PsGetProcessImageFileName 返回 ANSI 基名，最多 15 字符，
  // 对掩码匹配够用（notepad.exe / where.exe 都在范围内）。
  const char *image = PsGetProcessImageFileName(process->get());
  wchar_t exe[target::max_name_chars]{};
  for (std::size_t i = 0; i < target::max_name_chars - 1 && image[i] != '\0'; ++i)
    exe[i] = static_cast<wchar_t>(static_cast<unsigned char>(image[i]));

  bool matched = false;
  {
    std::scoped_lock guard(state.lock);
    for (const auto &rule : state.rules) {
      if (match::should_inject(exe, rule.include_mask, rule.exclude_mask)) {
        matched = true;
        break;
      }
    }
    // 登记跟踪槽，供后续基址记录与兜底重试用。
    if (state.targets.size() < max_tracked_targets) {
      target::record fresh;
      fresh.pid = pid;
      target::set_name(fresh, exe);
      fresh.matched = matched;
      fresh.is32 = process::is_wow64(process->get());
      try {
        state.targets.push_back(fresh);
      } catch (...) {
        LOG_WARN("跟踪槽分配失败 pid=0x{:X}", pid);
      }
    }
  }

  // 注入不在这里做：同步版本在通知回调里死锁。真正的注入由映像/线程通知
  // 投递到系统线程，那条路径已验证可用。
}

// --- 回调与注册 -------------------------------------------------------------
inline void process_callback(HANDLE parent, HANDLE pid,
                             BOOLEAN create) noexcept {
  (void)parent;
  on_process(pid, create);
}

inline void image_callback(PUNICODE_STRING name, HANDLE pid,
                           PIMAGE_INFO info) noexcept {
  on_image(name, pid, info);
}

inline void thread_callback(HANDLE pid, HANDLE tid, BOOLEAN create) noexcept {
  on_thread(pid, tid, create);
}

inline ntl::status register_all() noexcept {
  if (const auto st = PsSetCreateProcessNotifyRoutine(process_callback, FALSE);
      !NT_SUCCESS(st)) {
    LOG_ERROR("注册进程通知失败：0x{:08X}", static_cast<ULONG>(st));
    return ntl::status{st};
  }

  if (const auto st = PsSetLoadImageNotifyRoutine(image_callback);
      !NT_SUCCESS(st)) {
    LOG_ERROR("注册映像通知失败：0x{:08X}", static_cast<ULONG>(st));
    PsSetCreateProcessNotifyRoutine(process_callback, TRUE);
    return ntl::status{st};
  }

  if (const auto st = PsSetCreateThreadNotifyRoutine(thread_callback);
      !NT_SUCCESS(st)) {
    LOG_ERROR("注册线程通知失败：0x{:08X}", static_cast<ULONG>(st));
    PsRemoveLoadImageNotifyRoutine(image_callback);
    PsSetCreateProcessNotifyRoutine(process_callback, TRUE);
    return ntl::status{st};
  }

  LOG_INFO("通知回调已注册");
  return ntl::status::ok();
}

inline void unregister_all() noexcept {
  PsRemoveCreateThreadNotifyRoutine(thread_callback);
  PsRemoveLoadImageNotifyRoutine(image_callback);
  PsSetCreateProcessNotifyRoutine(process_callback, TRUE);
  LOG_INFO("通知回调已注销");
}

} // namespace injdrv::notify
