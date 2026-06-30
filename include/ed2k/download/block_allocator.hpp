#pragma once
#include <cstdint>
#include <optional>
#include <queue>
#include <vector>
#include <tuple>
#include "ed2k/core/hash.hpp"
namespace ed2k::download {

constexpr std::size_t AICH_BLOCK_SIZE = 184320; // 180 KiB per AICH block

class BlockAllocator {
 public:
  BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                 const std::optional<AICHHash>& root_hash);

  // Mark a small block done, returns true if the containing part is now fully done
  bool mark_block_done(std::size_t part_index, std::size_t aich_index);

  // Get next missing block -> (part_index, aich_index, start_byte, end_byte)
  std::optional<std::tuple<std::size_t, std::size_t, std::uint64_t, std::uint64_t>> next_block();

  // Is entire file complete?
  bool complete() const;

  // Count of missing blocks (for progress)
  std::size_t missing_count() const;

 private:
  std::uint64_t size_;
  std::vector<PartHash> part_hashes_;
  std::optional<AICHHash> root_hash_;
  // [part][aich_index] = done?
  std::vector<std::vector<bool>> done_;
  std::queue<std::pair<std::size_t,std::size_t>> pending_;
};

}
