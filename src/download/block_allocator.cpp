#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/part_file.hpp" // for PART_SIZE

namespace ed2k::download {

void BlockAllocator::init_done(std::uint64_t size) {
  done_.reserve(part_hashes_.size());
  for (std::size_t pi = 0; pi < part_hashes_.size(); ++pi) {
    std::uint64_t part_start = pi * PART_SIZE;
    std::uint64_t part_end = std::min((pi+1)*PART_SIZE, size);
    std::size_t num_blocks = static_cast<std::size_t>((part_end - part_start + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
    done_.emplace_back(num_blocks, false);
  }
}

void BlockAllocator::enqueue_missing() {
  for (std::size_t pi = 0; pi < done_.size(); ++pi) {
    for (std::size_t ai = 0; ai < done_[pi].size(); ++ai) {
      if (!done_[pi][ai]) pending_.emplace(pi, ai);
    }
  }
}

BlockAllocator::BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                               const std::optional<AICHHash>& root_hash)
  : size_(size), part_hashes_(part_hashes), root_hash_(root_hash) {
  init_done(size);
  enqueue_missing();
}

// 从 PartFile 已有块状态恢复:只把未完成块入 pending 队列
BlockAllocator::BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                               const std::optional<AICHHash>& root_hash, const PartFile& pf)
  : size_(size), part_hashes_(part_hashes), root_hash_(root_hash) {
  init_done(size);
  // 从 PartFile 恢复:已完成的块标 done
  for (std::size_t pi = 0; pi < done_.size(); ++pi) {
    for (std::size_t ai = 0; ai < done_[pi].size(); ++ai) {
      if (pf.is_block_done(pi, ai)) done_[pi][ai] = true;
    }
  }
  enqueue_missing();
}

bool BlockAllocator::mark_block_done(std::size_t part_index, std::size_t aich_index) {
  if (part_index >= done_.size()) return false;
  if (aich_index >= done_[part_index].size()) return false;
  done_[part_index][aich_index] = true;

  // check if whole part now done
  for (bool b : done_[part_index]) {
    if (!b) return false;
  }
  return true;
}

std::optional<std::tuple<std::size_t, std::size_t, std::uint64_t, std::uint64_t>>
BlockAllocator::next_block() {
  if (pending_.empty()) return std::nullopt;
  auto [pi, ai] = pending_.front();
  pending_.pop();

  std::uint64_t start = pi * PART_SIZE + ai * AICH_BLOCK_SIZE;
  std::uint64_t part_end = std::min((pi+1)*PART_SIZE, size_);
  std::uint64_t end = std::min(start + AICH_BLOCK_SIZE, part_end);
  return std::make_tuple(pi, ai, start, end);
}

bool BlockAllocator::complete() const {
  for (auto& part : done_) {
    for (bool b : part) {
      if (!b) return false;
    }
  }
  return true;
}

std::size_t BlockAllocator::missing_count() const {
  std::size_t cnt = 0;
  for (auto& part : done_) {
    for (bool b : part) {
      if (!b) cnt++;
    }
  }
  return cnt;
}

void BlockAllocator::requeue_block(std::size_t part_index, std::size_t aich_index) {
  pending_.emplace(part_index, aich_index);
}

}
