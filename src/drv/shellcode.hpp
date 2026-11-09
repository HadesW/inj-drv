// ============================================================================
// shellcode.hpp
// ----------------------------------------------------------------------------
// x64 注入桩生成。**逐条照搬老实现 injection.hpp:516-593 的指令序列和块布局**，
// 那份代码验证过，先对齐再谈简化。
//
// 块布局（与老实现一致）：
//   +0x000 代码
//   +0x100 HMODULE 句柄（8 字节）
//   +0x108 count  （4 字节，待加载 DLL 数）
//   +0x10C index  （4 字节，循环变量）
//   +0x110 UNICODE_STRING[count]（每条 16 字节）
//   +0x400 路径区（每条 0x300 字节，最多 16 条）
//
// 桩执行流：sub rsp,0x28 → 还原 patch_target 的 12 字节 → 循环 LdrLoadDll
//         → add rsp,0x28 → jmp patch_target
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace injdrv::shellcode {

inline constexpr std::size_t code_offset = 0x000;
inline constexpr std::size_t handle_offset = 0x100;
inline constexpr std::size_t count_offset = 0x108;
inline constexpr std::size_t index_offset = 0x10C;
inline constexpr std::size_t unicode_base = 0x110;
inline constexpr std::size_t path_base = 0x400;

inline constexpr std::size_t unicode_entry_size = 16;
inline constexpr std::size_t path_slot_size = 0x300;
inline constexpr std::size_t max_dlls = 16;
inline constexpr std::size_t block_size = 0x400 + path_slot_size * max_dlls;

// 打补丁时覆盖的字节数。x64：mov rax,imm64 + jmp rax = 10+2；
// x86：E9 rel32 = 5（老实现就是直接跳到桩基址）。
inline constexpr std::size_t patch_size = 12;
inline constexpr std::size_t patch_size32 = 5;

// 与老实现 build_jmp_stub64（injection.hpp:516-593）逐指令一致。
inline std::size_t build_jmp_stub64(std::uint8_t *code, std::uint64_t patch_target,
                                    std::uint64_t ldr_load_dll,
                                    std::uint64_t block_base,
                                    const std::uint8_t original[patch_size]) noexcept {
  const std::uint64_t index_addr = block_base + index_offset;
  const std::uint64_t count_addr = block_base + count_offset;
  const std::uint64_t unicode_addr = block_base + unicode_base;

  std::size_t o = 0;
  auto u32 = [&](std::uint32_t v) { std::memcpy(code + o, &v, 4); o += 4; };
  auto u64 = [&](std::uint64_t v) { std::memcpy(code + o, &v, 8); o += 8; };
  auto mov_rax = [&](std::uint64_t v) { code[o++] = 0x48; code[o++] = 0xB8; u64(v); };
  auto mov_rcx = [&](std::uint64_t v) { code[o++] = 0x48; code[o++] = 0xB9; u64(v); };
  auto mov_rdx = [&](std::uint64_t v) { code[o++] = 0x48; code[o++] = 0xBA; u64(v); };
  auto mov_r8 = [&](std::uint64_t v)  { code[o++] = 0x49; code[o++] = 0xB8; u64(v); };
  auto mov_r9 = [&](std::uint64_t v)  { code[o++] = 0x49; code[o++] = 0xB9; u64(v); };

  // sub rsp, 0x28
  code[o++] = 0x48; code[o++] = 0x83; code[o++] = 0xEC; code[o++] = 0x28;

  // 还原 patch_target 的 12 字节
  std::uint64_t original8 = 0;
  std::uint32_t original4 = 0;
  std::memcpy(&original8, original, 8);
  std::memcpy(&original4, original + 8, 4);
  mov_rax(patch_target);
  mov_rcx(original8);
  code[o++] = 0x48; code[o++] = 0x89; code[o++] = 0x08; // mov [rax], rcx
  code[o++] = 0xB9; u32(original4);                       // mov ecx, original4
  code[o++] = 0x89; code[o++] = 0x48; code[o++] = 0x08;   // mov [rax+8], ecx

  // index = 0
  mov_rax(index_addr);
  code[o++] = 0xC7; code[o++] = 0x00; u32(0); // mov dword [rax], 0

  // 循环开始
  const std::size_t loop_start = o;
  mov_rax(index_addr);
  code[o++] = 0x8B; code[o++] = 0x08;             // mov ecx, [rax]
  mov_rdx(count_addr);
  code[o++] = 0x3B; code[o++] = 0x0A;             // cmp ecx, [rdx]
  code[o++] = 0x0F; code[o++] = 0x83;
  const std::size_t jae_disp = o; o += 4;         // jae done

  // r8 = unicode_base + index * 16
  mov_rax(index_addr);
  code[o++] = 0x8B; code[o++] = 0x08;             // mov ecx, [rax]
  code[o++] = 0xC1; code[o++] = 0xE1; code[o++] = 0x04; // shl ecx, 4
  mov_r8(unicode_addr);
  code[o++] = 0x49; code[o++] = 0x01; code[o++] = 0xC8; // add r8, rcx

  // LdrLoadDll(NULL, 0, &unicode[index], &handle)
  code[o++] = 0x48; code[o++] = 0x31; code[o++] = 0xC9; // xor rcx, rcx
  code[o++] = 0x48; code[o++] = 0x31; code[o++] = 0xD2; // xor rdx, rdx
  mov_r9(block_base + handle_offset);
  mov_rax(ldr_load_dll);
  code[o++] = 0xFF; code[o++] = 0xD0;             // call rax

  // ++index
  mov_rax(index_addr);
  code[o++] = 0xFF; code[o++] = 0x00;             // inc dword [rax]
  code[o++] = 0xE9;
  const std::size_t jmp_disp = o; o += 4;         // jmp loop_start

  const std::size_t done = o;
  code[o++] = 0x48; code[o++] = 0x83; code[o++] = 0xC4; code[o++] = 0x28; // add rsp
  mov_rax(patch_target);
  code[o++] = 0xFF; code[o++] = 0xE0;             // jmp rax

  auto set_rel = [&](std::size_t disp_pos, std::size_t target) {
    const std::int32_t rel = static_cast<std::int32_t>(
        static_cast<std::int64_t>(target) -
        static_cast<std::int64_t>(disp_pos + 4));
    std::memcpy(code + disp_pos, &rel, 4);
  };
  set_rel(jae_disp, done);
  set_rel(jmp_disp, loop_start);

  return o;
}

// x86 多 DLL JMP stub：还原 patch_target 处 5 字节、逐个 stdcall LdrLoadDll
// 加载，然后跳回。逐指令照搬老实现 injection.hpp:659-729，块布局同 x64，
// 只是 UNICODE_STRING32 条目为 8 字节（Length/MaxLength/Buffer32）。
inline std::size_t build_jmp_stub32(std::uint8_t *code,
                                    std::uint32_t patch_target,
                                    std::uint32_t ldr_load_dll,
                                    std::uint32_t block_base,
                                    const std::uint8_t original[patch_size32]) noexcept {
  const std::uint32_t index_addr = block_base + index_offset;
  const std::uint32_t count_addr = block_base + count_offset;
  const std::uint32_t unicode_addr = block_base + unicode_base;

  std::size_t o = 0;
  auto u32 = [&](std::uint32_t v) { std::memcpy(code + o, &v, 4); o += 4; };
  auto mov_eax = [&](std::uint32_t v) { code[o++] = 0xB8; u32(v); };
  auto mov_edx = [&](std::uint32_t v) { code[o++] = 0xBA; u32(v); };

  std::uint32_t original4 = 0;
  std::memcpy(&original4, original, 4);

  // 保存 ebp，把栈对齐到 16 字节再调 stdcall。
  code[o++] = 0x55;                                     // push ebp
  code[o++] = 0x89; code[o++] = 0xE5;                   // mov ebp, esp
  code[o++] = 0x83; code[o++] = 0xE4; code[o++] = 0xF0; // and esp, -16

  // 还原 patch_target 的 5 字节
  code[o++] = 0xB9; u32(patch_target); // mov ecx, patch_target
  code[o++] = 0xB8; u32(original4);    // mov eax, original4
  code[o++] = 0x89; code[o++] = 0x01;  // mov [ecx], eax
  code[o++] = 0xB0; code[o++] = original[4]; // mov al, original[4]
  code[o++] = 0x88; code[o++] = 0x41; code[o++] = 0x04; // mov [ecx+4], al

  // index = 0
  mov_eax(index_addr);
  code[o++] = 0xC7; code[o++] = 0x00; u32(0); // mov dword [eax], 0

  const std::size_t loop_start = o;
  code[o++] = 0xA1; u32(index_addr);  // mov eax, [index_addr]
  code[o++] = 0x8B; code[o++] = 0x15; u32(count_addr); // mov edx, [count_addr]
  code[o++] = 0x39; code[o++] = 0xD0; // cmp eax, edx
  code[o++] = 0x0F; code[o++] = 0x83;
  const std::size_t jae_disp = o; o += 4;

  code[o++] = 0xA1; u32(index_addr); // mov eax, [index_addr]
  code[o++] = 0xC1; code[o++] = 0xE0; code[o++] = 0x03; // shl eax, 3
  code[o++] = 0x05; u32(unicode_addr); // add eax, unicode_base

  code[o++] = 0x68; u32(block_base + handle_offset); // push &handle
  code[o++] = 0x50;                          // push eax (&unicode[index])
  code[o++] = 0x6A; code[o++] = 0x00;        // push 0 (Flags)
  code[o++] = 0x6A; code[o++] = 0x00;        // push 0 (SearchPath)
  mov_edx(ldr_load_dll);
  code[o++] = 0xFF; code[o++] = 0xD2;        // call edx

  code[o++] = 0xFF; code[o++] = 0x05; u32(index_addr); // inc dword [index_addr]
  code[o++] = 0xE9;
  const std::size_t jmp_disp = o; o += 4;

  const std::size_t done = o;
  code[o++] = 0x89; code[o++] = 0xEC; // mov esp, ebp
  code[o++] = 0x5D;                   // pop ebp
  mov_eax(patch_target);
  code[o++] = 0xFF; code[o++] = 0xE0; // jmp eax

  auto set_rel = [&](std::size_t disp_pos, std::size_t target) {
    const std::int32_t rel = static_cast<std::int32_t>(
        static_cast<std::int64_t>(target) -
        static_cast<std::int64_t>(disp_pos + 4));
    std::memcpy(code + disp_pos, &rel, 4);
  };
  set_rel(jae_disp, done);
  set_rel(jmp_disp, loop_start);

  return o;
}

// x64 APC 桩：逐个 LdrLoadDll 加载后返回。作为用户态 APC 的 NormalRoutine
// 运行，没有补丁要还原。指令序列照老实现 injection.hpp:595-655。
inline std::size_t build_apc_stub64(std::uint8_t *code,
                                    std::uint64_t ldr_load_dll,
                                    std::uint64_t block_base) noexcept {
  const std::uint64_t index_addr = block_base + index_offset;
  const std::uint64_t count_addr = block_base + count_offset;
  const std::uint64_t unicode_addr = block_base + unicode_base;

  std::size_t o = 0;
  auto u32 = [&](std::uint32_t v) { std::memcpy(code + o, &v, 4); o += 4; };
  auto u64 = [&](std::uint64_t v) { std::memcpy(code + o, &v, 8); o += 8; };
  auto mov_rax = [&](std::uint64_t v) { code[o++] = 0x48; code[o++] = 0xB8; u64(v); };
  auto mov_rdx = [&](std::uint64_t v) { code[o++] = 0x48; code[o++] = 0xBA; u64(v); };
  auto mov_r8 = [&](std::uint64_t v)  { code[o++] = 0x49; code[o++] = 0xB8; u64(v); };
  auto mov_r9 = [&](std::uint64_t v)  { code[o++] = 0x49; code[o++] = 0xB9; u64(v); };

  // sub rsp, 0x28
  code[o++] = 0x48; code[o++] = 0x83; code[o++] = 0xEC; code[o++] = 0x28;

  // index = 0
  mov_rax(index_addr);
  code[o++] = 0xC7; code[o++] = 0x00; u32(0); // mov dword [rax], 0

  const std::size_t loop_start = o;
  mov_rax(index_addr);
  code[o++] = 0x8B; code[o++] = 0x08;             // mov ecx, [rax]
  mov_rdx(count_addr);
  code[o++] = 0x3B; code[o++] = 0x0A;             // cmp ecx, [rdx]
  code[o++] = 0x0F; code[o++] = 0x83;
  const std::size_t jae_disp = o; o += 4;         // jae done

  mov_rax(index_addr);
  code[o++] = 0x8B; code[o++] = 0x08;             // mov ecx, [rax]
  code[o++] = 0xC1; code[o++] = 0xE1; code[o++] = 0x04; // shl ecx, 4
  mov_r8(unicode_addr);
  code[o++] = 0x49; code[o++] = 0x01; code[o++] = 0xC8; // add r8, rcx

  // LdrLoadDll(NULL, 0, &unicode[index], &handle)
  code[o++] = 0x48; code[o++] = 0x31; code[o++] = 0xC9; // xor rcx, rcx
  code[o++] = 0x48; code[o++] = 0x31; code[o++] = 0xD2; // xor rdx, rdx
  mov_r9(block_base + handle_offset);
  mov_rax(ldr_load_dll);
  code[o++] = 0xFF; code[o++] = 0xD0;             // call rax

  // ++index
  mov_rax(index_addr);
  code[o++] = 0xFF; code[o++] = 0x00;             // inc dword [rax]
  code[o++] = 0xE9;
  const std::size_t jmp_disp = o; o += 4;         // jmp loop_start

  const std::size_t done = o;
  code[o++] = 0x48; code[o++] = 0x83; code[o++] = 0xC4; code[o++] = 0x28; // add rsp
  code[o++] = 0xC3;                               // ret

  auto set_rel = [&](std::size_t disp_pos, std::size_t target) {
    const std::int32_t rel = static_cast<std::int32_t>(
        static_cast<std::int64_t>(target) -
        static_cast<std::int64_t>(disp_pos + 4));
    std::memcpy(code + disp_pos, &rel, 4);
  };
  set_rel(jae_disp, done);
  set_rel(jmp_disp, loop_start);

  return o;
}

// x86 APC 桩：stdcall 的 NormalRoutine，返回时用 ret 12 清掉三个 APC 参数。
// 指令序列照老实现 injection.hpp:800-854。
inline std::size_t build_apc_stub32(std::uint8_t *code,
                                    std::uint32_t ldr_load_dll,
                                    std::uint32_t block_base) noexcept {
  const std::uint32_t index_addr = block_base + index_offset;
  const std::uint32_t count_addr = block_base + count_offset;
  const std::uint32_t unicode_addr = block_base + unicode_base;

  std::size_t o = 0;
  auto u32 = [&](std::uint32_t v) { std::memcpy(code + o, &v, 4); o += 4; };
  auto mov_eax = [&](std::uint32_t v) { code[o++] = 0xB8; u32(v); };
  auto mov_edx = [&](std::uint32_t v) { code[o++] = 0xBA; u32(v); };

  // 保存 ebp，把栈对齐到 16 字节再调 stdcall。
  code[o++] = 0x55;                                     // push ebp
  code[o++] = 0x89; code[o++] = 0xE5;                   // mov ebp, esp
  code[o++] = 0x83; code[o++] = 0xE4; code[o++] = 0xF0; // and esp, -16

  // index = 0
  mov_eax(index_addr);
  code[o++] = 0xC7; code[o++] = 0x00; u32(0);           // mov dword [eax], 0

  const std::size_t loop_start = o;
  code[o++] = 0xA1; u32(index_addr);  // mov eax, [index_addr]
  code[o++] = 0x8B; code[o++] = 0x15; u32(count_addr); // mov edx, [count_addr]
  code[o++] = 0x39; code[o++] = 0xD0; // cmp eax, edx
  code[o++] = 0x0F; code[o++] = 0x83;
  const std::size_t jae_disp = o; o += 4;

  code[o++] = 0xA1; u32(index_addr); // mov eax, [index_addr]
  code[o++] = 0xC1; code[o++] = 0xE0; code[o++] = 0x03; // shl eax, 3
  code[o++] = 0x05; u32(unicode_addr); // add eax, unicode_base

  code[o++] = 0x68; u32(block_base + handle_offset); // push &handle
  code[o++] = 0x50;                          // push eax (&unicode[index])
  code[o++] = 0x6A; code[o++] = 0x00;        // push 0 (Flags)
  code[o++] = 0x6A; code[o++] = 0x00;        // push 0 (SearchPath)
  mov_edx(ldr_load_dll);
  code[o++] = 0xFF; code[o++] = 0xD2;        // call edx

  code[o++] = 0xFF; code[o++] = 0x05; u32(index_addr); // inc dword [index_addr]
  code[o++] = 0xE9;
  const std::size_t jmp_disp = o; o += 4;

  const std::size_t done = o;
  code[o++] = 0x89; code[o++] = 0xEC;             // mov esp, ebp
  code[o++] = 0x5D;                               // pop ebp
  code[o++] = 0xC2; code[o++] = 0x0C; code[o++] = 0x00; // ret 12

  auto set_rel = [&](std::size_t disp_pos, std::size_t target) {
    const std::int32_t rel = static_cast<std::int32_t>(
        static_cast<std::int64_t>(target) -
        static_cast<std::int64_t>(disp_pos + 4));
    std::memcpy(code + disp_pos, &rel, 4);
  };
  set_rel(jae_disp, done);
  set_rel(jmp_disp, loop_start);

  return o;
}

// 写 count 与 UNICODE_STRING[]/路径区。32 位目标的条目是 8 字节
// （Length/MaxLength/Buffer32），64 位是 16 字节（Buffer64）。
template <bool Is32>
inline void write_payload_impl(std::uint8_t *code, std::uintptr_t block_base,
                               std::span<const std::wstring_view> paths) noexcept {
  constexpr std::size_t entry_size = Is32 ? 8 : unicode_entry_size;
  constexpr std::size_t buffer_offset = Is32 ? 4 : 8;

  const std::size_t count = paths.size() < max_dlls ? paths.size() : max_dlls;
  const std::uint32_t c32 = static_cast<std::uint32_t>(count);
  std::memcpy(code + count_offset, &c32, 4);

  for (std::size_t i = 0; i < count; ++i) {
    const std::size_t chars = paths[i].size() < (path_slot_size / 2 - 1)
                                  ? paths[i].size()
                                  : (path_slot_size / 2 - 1);

    auto *path = reinterpret_cast<wchar_t *>(code + path_base + i * path_slot_size);
    for (std::size_t k = 0; k < chars; ++k)
      path[k] = paths[i][k];
    path[chars] = L'\0';

    std::uint8_t *u = code + unicode_base + i * entry_size;
    const std::uint16_t length = static_cast<std::uint16_t>(chars * 2);
    const std::uint16_t max_length = static_cast<std::uint16_t>((chars + 1) * 2);
    std::memcpy(u + 0, &length, 2);
    std::memcpy(u + 2, &max_length, 2);

    const std::uintptr_t buffer_addr =
        block_base + path_base + i * path_slot_size;
    if constexpr (Is32) {
      const auto buffer32 = static_cast<std::uint32_t>(buffer_addr);
      std::memcpy(u + buffer_offset, &buffer32, 4);
    } else {
      const std::uint64_t buffer64 = static_cast<std::uint64_t>(buffer_addr);
      std::memcpy(u + buffer_offset, &buffer64, 8);
    }
  }
}

inline void write_payload(std::uint8_t *code, std::uint64_t block_base,
                          std::span<const std::wstring_view> paths) noexcept {
  write_payload_impl<false>(code, static_cast<std::uintptr_t>(block_base),
                            paths);
}

inline void write_payload32(std::uint8_t *code, std::uint32_t block_base,
                            std::span<const std::wstring_view> paths) noexcept {
  write_payload_impl<true>(code, static_cast<std::uintptr_t>(block_base), paths);
}

} // namespace injdrv::shellcode
