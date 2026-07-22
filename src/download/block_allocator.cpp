#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/part_file.hpp" // for PartFile recover ctor

namespace ed2k::download {

// per-part 块位图: done_[part][block_in_part]。每 part ceil(part_size/AICH_BLOCK_SIZE) 块,
// 块绝不跨 part 边界 —— 与 aMule SHAHashSet 两级树 per-part 叶序一致 (满 part 53 块, 末块 143360B)。
void BlockAllocator::init_done() {
  done_.clear();
  done_.resize(num_parts());
  for (std::size_t p = 0; p < num_parts(); ++p) {
    done_[p].assign(blocks_in_part(p), false);
  }
}

void BlockAllocator::enqueue_missing() {
  for (std::size_t p = 0; p < num_parts(); ++p) {
    for (std::size_t b = 0; b < done_[p].size(); ++b) {
      if (!done_[p][b]) pending_.push({p, b});
    }
  }
}

BlockAllocator::BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                               const std::optional<AICHHash>& root_hash)
  : size_(size), part_hashes_(part_hashes), root_hash_(root_hash) {
  init_done();
  enqueue_missing();
}

// 从 PartFile 已有块状态恢复: 只把未完成块入 pending 队列
BlockAllocator::BlockAllocator(std::uint64_t size, const std::vector<PartHash>& part_hashes,
                               const std::optional<AICHHash>& root_hash, const PartFile& pf)
  : size_(size), part_hashes_(part_hashes), root_hash_(root_hash) {
  init_done();
  for (std::size_t p = 0; p < num_parts(); ++p) {
    for (std::size_t b = 0; b < done_[p].size(); ++b) {
      if (pf.is_block_done(p, b)) done_[p][b] = true;
    }
  }
  enqueue_missing();
}

bool BlockAllocator::mark_block_done(std::size_t part, std::size_t block_in_part) {
  if (part >= done_.size() || block_in_part >= done_[part].size()) return false;
  done_[part][block_in_part] = true;
  return complete();
}

// 返回 (part, block_in_part, start, end): 块绝不跨 part 边界。
//   start = part*PART_SIZE + block_in_part*AICH_BLOCK_SIZE
//   end   = min(start + AICH_BLOCK_SIZE, part_end, size_)
std::optional<std::tuple<std::size_t, std::size_t, std::uint64_t, std::uint64_t>>
BlockAllocator::next_block() {
  if (pending_.empty()) return std::nullopt;
  auto [part, bip] = pending_.front();
  pending_.pop();

  std::uint64_t pstart = static_cast<std::uint64_t>(part) * PART_SIZE;
  std::uint64_t start = pstart + static_cast<std::uint64_t>(bip) * AICH_BLOCK_SIZE;
  std::uint64_t pend = pstart + part_size(part);   // part 边界 (≤ size_)
  std::uint64_t end = std::min(static_cast<std::uint64_t>(start) + AICH_BLOCK_SIZE, pend);
  return std::make_tuple(part, bip, start, end);
}

// raccoon: 扫描 pending_ 一轮, 跳过对端无该 part 的块(重入队尾), 取首个可服务块。
// 全轮无可服务块 → nullopt (源耗尽)。单网络线程 → initial 在扫描期稳定。
std::optional<std::tuple<std::size_t, std::size_t, std::uint64_t, std::uint64_t>>
BlockAllocator::next_block_for_parts(const std::vector<bool>& has_part) {
  std::size_t initial = pending_.size();
  for (std::size_t i = 0; i < initial; ++i) {
    if (pending_.empty()) break;
    auto [part, bip] = pending_.front();
    pending_.pop();
    if (part < has_part.size() && has_part[part]) {
      std::uint64_t pstart = static_cast<std::uint64_t>(part) * PART_SIZE;
      std::uint64_t start = pstart + static_cast<std::uint64_t>(bip) * AICH_BLOCK_SIZE;
      std::uint64_t pend = pstart + part_size(part);
      std::uint64_t end = std::min(static_cast<std::uint64_t>(start) + AICH_BLOCK_SIZE, pend);
      return std::make_tuple(part, bip, start, end);
    }
    pending_.push({part, bip});   // 对端无此 part → 重入队尾, 试下一块
  }
  return std::nullopt;
}

// 审计 C6: 连续调用 next_block_for_parts 最多 max_count 次, 遇 nullopt(源耗尽)提前停止。
// 不做任何"凑数"或失败回滚——每个返回项都已从 pending_ 移出(与 next_block_for_parts 单块语义
// 一致), 调用方对未被实际服务的项负责 requeue_block。
std::vector<std::tuple<std::size_t, std::size_t, std::uint64_t, std::uint64_t>>
BlockAllocator::next_blocks_for_parts(const std::vector<bool>& has_part, std::size_t max_count) {
  std::vector<std::tuple<std::size_t, std::size_t, std::uint64_t, std::uint64_t>> out;
  out.reserve(max_count);
  for (std::size_t i = 0; i < max_count; ++i) {
    auto nb = next_block_for_parts(has_part);
    if (!nb) break;
    out.push_back(*nb);
  }
  return out;
}

bool BlockAllocator::complete() const {
  for (const auto& pv : done_) {
    for (bool b : pv) {
      if (!b) return false;
    }
  }
  return true;
}

std::size_t BlockAllocator::missing_count() const {
  std::size_t cnt = 0;
  for (const auto& pv : done_) {
    for (bool b : pv) {
      if (!b) ++cnt;
    }
  }
  return cnt;
}

void BlockAllocator::requeue_block(std::size_t part, std::size_t block_in_part) {
  pending_.push({part, block_in_part});
}

}
