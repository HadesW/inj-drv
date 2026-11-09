// ============================================================================
// dispatch.hpp
// ----------------------------------------------------------------------------
// 通用功能分发：驱动只暴露一个 IOCTL 码（protocol::control_code），具体命令由
// 请求信封里的 opcode 路由。以后新增功能（注入、卸载等）只需要：
//   1. 在 protocol.hpp 加 opcode 和载荷结构
//   2. 写一个 handler： ntl::status(const Req&, Resp&)
//   3. dispatch.add<command<...>, handler>();
// 不新增 IOCTL 码，也不改动本文件。
//
// 分发级别出错（IOCTL 码不对、信封坏了、opcode 未注册）以 IRP 状态返回且不写
// 应答；命令自己返回的失败会写回应答，并放进 response_header::status，IRP 状态
// 保持 STATUS_SUCCESS——用户态总能拿到 request_id 回显和命令级状态。
// ============================================================================
#pragma once

// logger.hpp 必须排在 ntl 头之前：它引入 ntifs.h/ntddk.h，否则 ntl 头带来的
// wdm.h 会把 ntddk.h 挡掉，PsGetCurrentThreadId 之类就没了。
#include "../shared/logger.hpp"

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <ntl/device>
#include <ntl/ioctl>
#include <ntl/pool_allocator>
#include <ntl/remove_lock>
#include <ntl/status>

#include "../shared/protocol.hpp"

namespace injdrv {

// 命令契约：Op 是 opcode，Req/Resp 是请求与应答结构。
template <protocol::opcode Op, class Req, class Resp> struct command {
  using request = Req;
  using response = Resp;
  static constexpr protocol::opcode code = Op;
};

namespace detail {

template <class T>
concept request_like = std::is_trivially_copyable_v<T> && requires(const T &v) {
  { v.header.size } -> std::convertible_to<std::uint32_t>;
  { v.header.opcode } -> std::convertible_to<std::uint32_t>;
  { v.header.request_id } -> std::convertible_to<std::uint64_t>;
};

template <class T>
concept response_like = std::is_trivially_copyable_v<T> && requires(T &v) {
  { v.header.size } -> std::convertible_to<std::uint32_t>;
  { v.header.opcode } -> std::convertible_to<std::uint32_t>;
  { v.header.status } -> std::convertible_to<std::uint32_t>;
  { v.header.request_id } -> std::convertible_to<std::uint64_t>;
};

} // namespace detail

class dispatcher {
public:
  static constexpr std::size_t capacity = 16;

  dispatcher() = default;
  dispatcher(const dispatcher &) = delete;
  dispatcher &operator=(const dispatcher &) = delete;

  // Handler 形如 ntl::status(const Req&, Resp&)，作为模板参数固化，
  // 不占用条目存储，也不需要函数指针转换。
  template <class Cmd, auto Handler> void add() noexcept {
    using request = typename Cmd::request;
    using response = typename Cmd::response;

    static_assert(detail::request_like<request>,
                  "command request must start with protocol::request_header");
    static_assert(detail::response_like<response>,
                  "command response must start with protocol::response_header");
    static_assert(std::is_invocable_r_v<ntl::status, decltype(Handler),
                                        const request &, response &>,
                  "handler must match ntl::status(const Req&, Resp&)");

    NT_ASSERT(count_ < capacity);
    if (count_ >= capacity) {
      LOG_ERROR("分发表已满（capacity={}），拒绝注册 opcode 0x{:X}", capacity,
                static_cast<std::uint32_t>(Cmd::code));
      return;
    }

    entries_[count_++] = entry{Cmd::code, &invoke<Cmd, Handler>};
  }

  ntl::status dispatch(const ntl::device_control::code &code,
                       const ntl::device_control::in_buffer &in,
                       ntl::device_control::out_buffer &out) noexcept {
    auto guard = lock_.acquire();
    if (!guard) {
      out.clear();
      return static_cast<NTSTATUS>(guard.status());
    }

    if (!(code == protocol::control_code)) {
      out.clear();
      LOG_WARN("拒绝未知 IOCTL 0x{:08X} (type={} function={})", code.value,
               code.device_type(), code.function());
      return STATUS_INVALID_DEVICE_REQUEST;
    }

    const auto *header = in.as<protocol::request_header>();
    if (header == nullptr) {
      out.clear();
      LOG_WARN("请求太短：{} 字节，至少要 {}", in.size,
               sizeof(protocol::request_header));
      return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (header->size != in.size) {
      out.clear();
      LOG_WARN("信封 size {} 与缓冲区 {} 不一致 (request_id=0x{:X})",
               header->size, in.size, header->request_id);
      return STATUS_INFO_LENGTH_MISMATCH;
    }

    const entry *found = find(static_cast<protocol::opcode>(header->opcode));
    if (found == nullptr) {
      out.clear();
      LOG_WARN("未注册的 opcode 0x{:X} (request_id=0x{:X})", header->opcode,
               header->request_id);
      return STATUS_INVALID_DEVICE_REQUEST;
    }

    LOG_DEBUG("分发 opcode=0x{:X} request_id=0x{:X} size={}", header->opcode,
              header->request_id, in.size);

    return found->invoke(in.ptr, in.size, out);
  }

  // 卸载路径：停止接收新请求并等在途请求跑完。
  void shutdown() noexcept { lock_.release_and_wait(); }

private:
  struct entry {
    protocol::opcode code;
    ntl::status (*invoke)(const void *request, std::size_t request_size,
                          ntl::device_control::out_buffer &out);
  };

  const entry *find(protocol::opcode code) const noexcept {
    for (std::size_t i = 0; i < count_; ++i) {
      if (entries_[i].code == code)
        return &entries_[i];
    }
    return nullptr;
  }

  template <class Cmd, auto Handler>
  static ntl::status invoke(const void *request, std::size_t request_size,
                            ntl::device_control::out_buffer &out) noexcept {
    using req_t = typename Cmd::request;
    using resp_t = typename Cmd::response;

    if (request_size != sizeof(req_t)) {
      out.clear();
      LOG_WARN("opcode 0x{:X} 请求长度 {} 与结构体 {} 不符",
               static_cast<std::uint32_t>(Cmd::code), request_size,
               sizeof(req_t));
      return STATUS_INFO_LENGTH_MISMATCH;
    }

    const req_t &req = *static_cast<const req_t *>(request);

    resp_t resp{};
    const ntl::status command_status = Handler(req, resp);

    resp.header.size = static_cast<std::uint32_t>(sizeof(resp_t));
    resp.header.opcode = static_cast<std::uint32_t>(Cmd::code);
    resp.header.status =
        static_cast<std::uint32_t>(static_cast<NTSTATUS>(command_status));
    resp.header.request_id = req.header.request_id;

    if (!out.write(resp)) {
      out.clear();
      LOG_WARN("opcode 0x{:X} 应答 {} 字节装不进输出缓冲区",
               static_cast<std::uint32_t>(Cmd::code), sizeof(resp_t));
      return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
  }

  std::array<entry, capacity> entries_{};
  std::size_t count_ = 0;
  ntl::remove_lock lock_{ntl::pool_tag("inJd")};
};

} // namespace injdrv
