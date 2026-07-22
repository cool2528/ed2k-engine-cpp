#pragma once
#include <cstdint>
#include <span>
#include <utility>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/codec/tag.hpp"
#include "ed2k/util/error.hpp"
namespace ed2k {
struct KnownFileEntry {
  std::uint32_t date=0; FileHash hash; std::vector<PartHash> part_hashes;
  std::uint64_t size=0; std::vector<codec::Tag> tags;
  auto operator<=>(const KnownFileEntry&) const = default;
};
tl::expected<std::vector<KnownFileEntry>,std::error_code> parse_known_met(std::span<const std::byte>);
std::vector<std::byte> write_known_met(std::span<const KnownFileEntry>);
struct PartFileState {
  FileHash hash; std::vector<PartHash> part_hashes;
  std::uint64_t size=0;
  std::vector<std::pair<std::uint64_t,std::uint64_t>> gaps;
  std::vector<codec::Tag> tags;
  // E1: 未完成 part 的块级完成位图 (part_index -> 该 part 内每块是否已下载, 下标即 block_in_part)。
  // 仅覆盖"整 part 未完成但已有部分块写入"的情形; 已完成 part 不出现在此列表(其状态已由不落在
  // gaps 内表达)。元素用 uint8_t(0/1) 而非 vector<bool>, 避开位域代理类型在 DTO 层的额外复杂度
  // ——真正的按位打包发生在 known_part_met.cpp 的 wire 编码阶段(FT_INTERNAL_PARTIAL_BLOCKS)。
  // 旧版 .part.met(无此 tag)解析后本字段保持空 vector, 与"无块级信息可恢复"语义一致(向后兼容)。
  std::vector<std::pair<std::uint32_t,std::vector<std::uint8_t>>> partial_blocks;
  auto operator<=>(const PartFileState&) const = default;
};
tl::expected<PartFileState,std::error_code> parse_part_met(std::span<const std::byte>);
std::vector<std::byte> write_part_met(const PartFileState&);
}
