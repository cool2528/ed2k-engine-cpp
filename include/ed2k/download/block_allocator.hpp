#pragma once
#include <cstdint>
#include <optional>
#include <queue>
#include <vector>
#include <tuple>
#include <utility>
#include "ed2k/core/hash.hpp"
#include "ed2k/hash/aich_hasher.hpp"   // AICH_BLOCK_SIZE / PART_SIZE
namespace ed2k::download { class PartFile; }
namespace ed2k::download {

// AICH block base = ed2k::AICH_BLOCK_SIZE (aich_hasher.hpp); top-level part base = ed2k::PART_SIZE.
// Per-part block model: blocks never cross part boundaries, each part has ceil(part_size/AICH_BLOCK_SIZE) blocks
// (full part = 53 blocks, last block 143360B). Consistent with aMule SHAHashSet two-level tree per-part leaf order.

class BlockAllocator {
 public:
  BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                 const std::optional<AICHHash>& root_hash);
  // Restore from PartFile's existing block state: only enqueue incomplete blocks into pending queue
  BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                 const std::optional<AICHHash>& root_hash, const PartFile& pf);

  // Mark a per-part block done; returns true if the whole file is now complete
  bool mark_block_done(std::size_t part, std::size_t block_in_part);

  // Get next missing block -> (part, block_in_part, start_byte, end_byte).
  // Blocks never cross parts: end = min(start+AICH_BLOCK_SIZE, part_end, size).
  std::optional<std::tuple<std::size_t, std::size_t, std::uint64_t, std::uint64_t>> next_block();

  // Multi-source: get next block where the peer has the part. Scans pending_ queue (at most one full pass),
  // skips blocks where has_part[part]==false (re-enqueued to tail), returns first serviceable block (dequeued);
  // if no serviceable block in full pass -> nullopt (source exhausted). Single network thread access -> no lock (same as next_block).
  std::optional<std::tuple<std::size_t, std::size_t, std::uint64_t, std::uint64_t>>
    next_block_for_parts(const std::vector<bool>& has_part);

  // Is entire file complete?
  bool complete() const;

  // Count of missing blocks (for progress)
  std::size_t missing_count() const;

  // Re-enqueue bad block to pending queue tail (corruption recovery: retry N times with same peer then switch source, see T6)
  void requeue_block(std::size_t part, std::size_t block_in_part);

 private:
  std::uint64_t size_;
  std::vector<PartHash> part_hashes_;
  std::optional<AICHHash> root_hash_;
  std::vector<std::vector<bool>> done_;      // done_[part][block_in_part]; blocks never cross parts
  std::queue<std::pair<std::size_t,std::size_t>> pending_;  // (part, block_in_part)

  std::size_t num_parts() const {
    return static_cast<std::size_t>((size_ + PART_SIZE - 1) / PART_SIZE);
  }
  std::uint64_t part_size(std::size_t part) const {
    std::uint64_t base = static_cast<std::uint64_t>(part) * PART_SIZE;
    if (base >= size_) return 0;
    return std::min(PART_SIZE, size_ - base);
  }
  std::size_t blocks_in_part(std::size_t part) const {
    return static_cast<std::size_t>((part_size(part) + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
  }

  void init_done();       // Initialize done_ from size_/num_parts (all false, per-part)
  void enqueue_missing(); // Enqueue blocks marked false in done_ into pending_ (part-major order)
};

}
