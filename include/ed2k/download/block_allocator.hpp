#pragma once
#include <cstdint>
#include <optional>
#include <queue>
#include <vector>
#include <tuple>
#include "ed2k/core/hash.hpp"
#include "ed2k/download/part_file.hpp"
namespace ed2k::download {

constexpr std::size_t AICH_BLOCK_SIZE = 184320; // 180 KiB per AICH block

class BlockAllocator {
 public:
  BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                 const std::optional<AICHHash>& root_hash);
  // 从 PartFile 已有块状态恢复:只把未完成块入 pending 队列
  BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                 const std::optional<AICHHash>& root_hash, const PartFile& pf);

  // Mark a flat whole-file block done; returns true if the whole file is now complete
  bool mark_block_done(std::size_t global_block);

  // Get next missing block -> (global_block, start_byte, end_byte); end is size-capped, NOT part-capped
  std::optional<std::tuple<std::size_t, std::uint64_t, std::uint64_t>> next_block();

  // Is entire file complete?
  bool complete() const;

  // Count of missing blocks (for progress)
  std::size_t missing_count() const;

  // 坏块重入 pending 队列尾部(损坏恢复:同 peer 重试 N 次后换源,见 T6)
  void requeue_block(std::size_t global_block);

 private:
  std::uint64_t size_;
  std::vector<PartHash> part_hashes_;
  std::optional<AICHHash> root_hash_;
  std::vector<bool> done_;                  // FLAT 整文件位图, size = ceil(size/AICH_BLOCK_SIZE)
  std::queue<std::size_t> pending_;         // global block indices

  void init_done(std::uint64_t size);   // 按 size 初始化 done_(全 false, flat)
  void enqueue_missing();               // 把 done_ 中 false 的块入 pending_
};

}
