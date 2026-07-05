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
  auto operator<=>(const PartFileState&) const = default;
};
tl::expected<PartFileState,std::error_code> parse_part_met(std::span<const std::byte>);
std::vector<std::byte> write_part_met(const PartFileState&);
}
