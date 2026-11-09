// ============================================================================
// protocol.hpp
// ----------------------------------------------------------------------------
// 内核态驱动与用户态控制器共享的协议定义。
// 内核侧先包含 <ntddk.h>/<wdm.h>，用户侧先包含 <windows.h>/<winioctl.h>，
// 两侧都提供 CTL_CODE。所有结构体 1 字节对齐，保证两侧布局一致。
//
// 协议只有一个 IOCTL 码，命令由信封里的 opcode 分发；以后新增功能（注入、
// 卸载等）只需新增 opcode 和载荷结构，不再新增 IOCTL 码。
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdint>

#ifndef CTL_CODE
#error Include <wdm.h> in kernel mode or <winioctl.h> in user mode first.
#endif

namespace injdrv::protocol {

// --- 设备命名 ---------------------------------------------------------------
inline constexpr wchar_t device_name[] = L"injdrv";
inline constexpr wchar_t device_name_nt[] = L"\\Device\\injdrv";
inline constexpr wchar_t symlink_name_nt[] = L"\\DosDevices\\injdrv";
inline constexpr wchar_t user_path[] = L"\\\\.\\injdrv";

// --- 版本 -------------------------------------------------------------------
inline constexpr std::uint32_t driver_version = 0x00010000; // 1.0.0
inline constexpr std::uint32_t protocol_version = 0x0001;

inline constexpr std::uint32_t build_debug = 0x00000001;
inline constexpr std::uint32_t build_release = 0x00000002;

// 由工程在 Debug 配置下定义 INJDRV_DEBUG。内核工程不定义 _DEBUG/NDEBUG，
// 所以不能靠标准宏判断构建类型。
#if defined(INJDRV_DEBUG)
inline constexpr std::uint32_t build_flags = build_debug;
#else
inline constexpr std::uint32_t build_flags = build_release;
#endif

// --- 唯一 IOCTL 码 -----------------------------------------------------------
inline constexpr unsigned long ioctl_device_type = FILE_DEVICE_UNKNOWN;
inline constexpr unsigned long ioctl_function = 0x800;
inline constexpr unsigned long ioctl_access = FILE_READ_DATA | FILE_WRITE_DATA;
inline constexpr unsigned long control_code =
    CTL_CODE(ioctl_device_type, ioctl_function, METHOD_BUFFERED, ioctl_access);

// --- 身份校验常量 -----------------------------------------------------------
// magic 用来挡住随便往设备号上发的包；checksum_secret 参与校验和，让客户端
// 能确认应答来自本项目构建的驱动而不是别的同名设备。
inline constexpr std::uint32_t request_magic = 0x314A4E49; // "INJ1"
inline constexpr std::uint32_t reply_magic = 0x324A4E49;  // "INJ2"
inline constexpr std::uint64_t checksum_secret = 0x9E3779B97F4A7C15ull;

// --- 功能号 -----------------------------------------------------------------
enum class opcode : std::uint32_t {
  ping = 0x0001,
  inject_add = 0x0002,
  inject_remove = 0x0003,
  inject_enum = 0x0004,
  restore = 0x0005,
  allow_stop = 0x0006,
};

// --- 注入标志位 -------------------------------------------------------------
inline constexpr std::uint32_t inject_system_processes = 0x0001;
inline constexpr std::uint32_t inject_permanently = 0x0002;
inline constexpr std::uint32_t inject_metro_apps = 0x0004;
inline constexpr std::uint32_t inject_via_iat_patching = 0x0008;
inline constexpr std::uint32_t inject_allow_thread = 0x0010;
inline constexpr std::uint32_t inject_via_apc = 0x0020;

inline constexpr std::size_t max_path_chars = 260;
inline constexpr std::size_t max_mask_chars = 256;

// --- 信封 -------------------------------------------------------------------
#pragma pack(push, 1)

// 24 字节：留 flags/reserved 给将来的鉴权、加密或分片。
struct request_header {
  std::uint32_t size;       // 整个请求字节数
  std::uint32_t opcode;     // protocol::opcode
  std::uint32_t flags;      // 预留
  std::uint32_t reserved;   // 预留
  std::uint64_t request_id; // 客户端随机，驱动回显以便配对
};
static_assert(sizeof(request_header) == 24, "request_header must stay 24 bytes");

struct response_header {
  std::uint32_t size;       // 整个应答字节数
  std::uint32_t opcode;     // 回显请求的 opcode
  std::uint32_t status;     // 命令级 NTSTATUS
  std::uint32_t flags;      // 预留
  std::uint64_t request_id; // 回显请求的 request_id
};
static_assert(sizeof(response_header) == 24,
              "response_header must stay 24 bytes");

// --- ping：确认驱动已加载并完成身份验证 -------------------------------------
struct ping_request {
  request_header header;
  std::uint64_t nonce;         // 客户端随机数，驱动必须原样回显
  std::uint32_t magic;         // 必须等于 request_magic
  std::uint32_t client_version;
};
static_assert(sizeof(ping_request) == 40, "ping_request must stay 40 bytes");

struct ping_response {
  response_header header;
  std::uint64_t nonce;         // 回显客户端 nonce
  std::uint64_t uptime_ms;     // 驱动加载至今的毫秒数
  std::uint64_t checksum;      // 见 ping_checksum()
  std::uint32_t magic;         // 回 reply_magic
  std::uint32_t protocol;      // protocol_version
  std::uint32_t driver_version;
  std::uint32_t build_flags;   // build_debug / build_release
};
static_assert(sizeof(ping_response) == 64, "ping_response must stay 64 bytes");

// --- 注入规则 ---------------------------------------------------------------
// 定长布局，两侧二进制一致，METHOD_BUFFERED 契约精确。
struct dll_item {
  std::uint32_t size;          // sizeof(dll_item)
  std::uint32_t flags;         // inject_* 标志位
  std::uint32_t session;       // session_all 表示所有会话
  std::uint32_t x86_alloc_addr;// x86 进程的分配首选地址（0 表示默认）
  std::uint32_t process_id;    // 枚举时由驱动回填
  std::uint32_t reserved;
  wchar_t name[max_path_chars];          // DLL 完整文件路径
  wchar_t include_mask[max_mask_chars];  // '|' 分隔的目标进程掩码
  wchar_t exclude_mask[max_mask_chars];  // '|' 分隔的排除进程掩码
};
static_assert(sizeof(dll_item) ==
              24 + sizeof(wchar_t) * (max_path_chars + 2 * max_mask_chars));

inline constexpr std::uint32_t session_all = 0xFFFFFFFFu;

inline void init_dll_item(dll_item &item) noexcept {
  item.size = static_cast<std::uint32_t>(sizeof(dll_item));
  item.flags = 0;
  item.session = session_all;
  item.x86_alloc_addr = 0;
  item.process_id = 0;
  item.reserved = 0;
  item.name[0] = L'\0';
  item.include_mask[0] = L'\0';
  item.exclude_mask[0] = L'\0';
}

struct inject_add_request {
  request_header header;
  dll_item item;
};

struct inject_add_response {
  response_header header;
  std::uint32_t accepted;      // 1=新增，0=同名已存在被忽略
  std::uint32_t active_count;  // 当前规则总数
  std::uint32_t reserved[2];
};

// 只用 item.name 做精确匹配删除。
using inject_remove_request = inject_add_request;

struct inject_remove_response {
  response_header header;
  std::uint32_t removed;       // 1=删掉，0=没找到
  std::uint32_t active_count;
  std::uint32_t reserved[2];
};

struct inject_enum_request {
  request_header header;
  std::uint32_t index;         // 0 起
  std::uint32_t reserved;
};

struct inject_enum_response {
  response_header header;
  dll_item item;               // 命中时回填，process_id 置 0
};

// --- 还原 IAT 注入 -----------------------------------------------------------
// 把目标模块的导入目录/BoundImports/校验和恢复原值，并释放追加的导入表。
// process_id 为 0 表示还原所有记录的进程。
struct restore_request {
  request_header header;
  std::uint32_t process_id;
  std::uint32_t reserved;
};

struct restore_response {
  response_header header;
  std::uint32_t restored;      // 成功还原的模块数
  std::uint32_t active;        // 仍处于未还原状态的模块数
  std::uint32_t reserved[2];
};

// --- 卸载开关 ---------------------------------------------------------------
// false 时清掉 DriverObject->DriverUnload，sc stop 会失败；true 时恢复。
// 默认允许卸载，避免调试流程被锁死。
struct allow_stop_request {
  request_header header;
  std::uint32_t allow;         // 0=禁止卸载，1=允许
  std::uint32_t reserved;
};

struct allow_stop_response {
  response_header header;
  std::uint32_t allowed;       // 当前状态：1=允许卸载
  std::uint32_t reserved[3];
};

#pragma pack(pop)

// --- 校验和 -----------------------------------------------------------------
// 纯计算，内核/用户态都能跑，不依赖任何 OS API。
inline std::uint64_t ping_checksum(std::uint64_t nonce, std::uint64_t uptime_ms,
                                   std::uint32_t magic,
                                   std::uint32_t protocol_ver,
                                   std::uint32_t driver_ver,
                                   std::uint32_t build_kind) noexcept {
  std::uint64_t h = checksum_secret ^ nonce;

  const auto mix = [&h](std::uint64_t v) {
    h ^= v;
    h *= 0x100000001B3ull; // FNV-1a 素数
    h ^= h >> 33;
    h *= 0xFF51AFD7ED558CCDull;
    h ^= h >> 29;
  };

  mix(uptime_ms);
  mix((static_cast<std::uint64_t>(magic) << 32) | protocol_ver);
  mix((static_cast<std::uint64_t>(driver_ver) << 32) | build_kind);
  mix(0xA5A5A5A5A5A5A5A5ull);

  return h;
}

inline std::uint64_t ping_checksum(const ping_response &reply) noexcept {
  return ping_checksum(reply.nonce, reply.uptime_ms, reply.magic, reply.protocol,
                       reply.driver_version, reply.build_flags);
}

} // namespace injdrv::protocol
