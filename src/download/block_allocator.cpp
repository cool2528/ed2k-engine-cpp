#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/part_file.hpp" // for PART_SIZE

namespace ed2k::download {

// FLAT 整文件块位图: num_blocks = ceil(size/AICH_BLOCK_SIZE)。
// PART_SIZE 不是 AICH_BLOCK_SIZE 的整数倍, 故块可跨越 part 边界(与 aich_hash_bytes / AICHChecker 一致)。
void BlockAllocator::init_done(std::uint64_t size) {
  std::size_t num_blocks = static_cast<std::size_t>((size + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
  done_.assign(num_blocks, false);
}

void BlockAllocator::enqueue_missing() {
  for (std::size_t g = 0; g < done_.size(); ++g) {
    if (!done_[g]) pending_.push(g);
  }
}

BlockAllocator::BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                               const std::optional<AICHHash>& root_hash)
  : size_(size), part_hashes_(part_hashes), root_hash_(root_hash) {
  init_done(size);
  enqueue_missing();
}

// 从 PartFile 已有块状态恢复: 只把未完成块入 pending 队列
BlockAllocator::BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                               const std::optional<AICHHash>& root_hash, const PartFile& pf)
  : size_(size), part_hashes_(part_hashes), root_hash_(root_hash) {
  init_done(size);
  for (std::size_t g = 0; g < done_.size(); ++g) {
    if (pf.is_block_done(g)) done_[g] = true;
  }
  enqueue_missing();
}

bool BlockAllocator::mark_block_done(std::size_t global_block) {
  if (global_block >= done_.size()) return false;
  done_[global_block] = true;
  return complete();
}

// 返回 (global, start, end): start = global*AICH_BLOCK_SIZE, end = min(start+AICH_BLOCK_SIZE, size_),
// 绝不按 part 截断 —— 跨界块的 end 可越过下一个 part 的起点。
std::optional<std::tuple<std::size_t, std::uint64_t, std::uint64_t>>
BlockAllocator::next_block() {
  if (pending_.empty()) return std::nullopt;
  std::size_t global = pending_.front();
  pending_.pop();

  std::uint64_t start = global * AICH_BLOCK_SIZE;
  std::uint64_t end = std::min(start + AICH_BLOCK_SIZE, size_);
  return std::make_tuple(global, start, end);
}

bool BlockAllocator::complete() const {
  for (bool b : done_) {
    if (!b) return false;
  }
  return true;
}

std::size_t BlockAllocator::missing_count() const {
  std::size_t cnt = 0;
  for (bool b : done_) {
    if (!b) cnt++;
  }
  return cnt;
}

void BlockAllocator::requeue_block(std::size_t global_block) {
  pending_.push(global_block);
}

}
