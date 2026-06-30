#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/part_file.hpp" // for PART_SIZE

namespace ed2k::download {

BlockAllocator::BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                               const std::optional<AICHHash>& root_hash)
  : size_(size), part_hashes_(part_hashes), root_hash_(root_hash) {

  done_.reserve(part_hashes.size());
  for (std::size_t pi = 0; pi < part_hashes.size(); ++pi) {
    std::uint64_t part_start = pi * PART_SIZE;
    std::uint64_t part_end = std::min((pi+1)*PART_SIZE, size_);
    std::size_t num_blocks = static_cast<std::size_t>((part_end - part_start + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
    done_.emplace_back(num_blocks, false);
    for (std::size_t ai = 0; ai < num_blocks; ++ai) {
      pending_.emplace(pi, ai);
    }
  }
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

}
