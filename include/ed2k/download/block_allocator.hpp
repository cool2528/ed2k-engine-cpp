#pragma once
#include <cstdint>
#include <optional>
#include <queue>
#include <vector>
#include <tuple>
#include <utility>
#include "ed2k/core/hash.hpp"
#include "ed2k/hash/aich_hasher.hpp"   // AICH_BLOCK_SIZE / PART_SIZE 单一定义源
#include "ed2k/download/part_file.hpp"
namespace ed2k::download {

// AICH 块基 = ed2k::AICH_BLOCK_SIZE（aich_hasher.hpp）；顶层 part 基 = ed2k::PART_SIZE。
// per-part 块模型：块绝不跨 part 边界，每 part ceil(part_size/AICH_BLOCK_SIZE) 块
// （满 part = 53 块，末块 143360B）。与 aMule SHAHashSet 两级树 per-part 叶序一致。

class BlockAllocator {
 public:
  BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                 const std::optional<AICHHash>& root_hash);
  // 从 PartFile 已有块状态恢复:只把未完成块入 pending 队列
  BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                 const std::optional<AICHHash>& root_hash, const PartFile& pf);

  // Mark a per-part block done; returns true if the whole file is now complete
  bool mark_block_done(std::size_t part, std::size_t block_in_part);

  // Get next missing block -> (part, block_in_part, start_byte, end_byte)。
  // 块绝不跨 part：end = min(start+AICH_BLOCK_SIZE, part_end, size)。
  std::optional<std::tuple<std::size_t, std::size_t, std::uint64_t, std::uint64_t>> next_block();

  // Is entire file complete?
  bool complete() const;

  // Count of missing blocks (for progress)
  std::size_t missing_count() const;

  // 坏块重入 pending 队列尾部(损坏恢复:同 peer 重试 N 次后换源,见 T6)
  void requeue_block(std::size_t part, std::size_t block_in_part);

 private:
  std::uint64_t size_;
  std::vector<PartHash> part_hashes_;
  std::optional<AICHHash> root_hash_;
  std::vector<std::vector<bool>> done_;      // done_[part][block_in_part]; 块不跨 part
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

  void init_done();       // 按 size_/num_parts 初始化 done_(全 false, per-part)
  void enqueue_missing(); // 把 done_ 中 false 的块入 pending_(part-major 序)
};

}
