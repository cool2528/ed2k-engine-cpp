#include "ed2k/download/aich_checker.hpp"
#include "ed2k/crypto/sha1.hpp"
#include <optional>
#include <algorithm>

namespace ed2k::download {
namespace {
using Digest = std::array<std::byte, 20>;

Digest sha1_cat(const Digest& l, const Digest& r) {
  crypto::SHA1 up;
  up.update(l);
  up.update(r);
  return up.finish();
}

std::uint64_t blocks_in_part(std::uint64_t part_size) {
  return (part_size + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;
}

// 两级叶序（part-major：part0-block0..part0-last, part1-block0...）→ 目标块字节偏移。
std::uint64_t target_offset(std::uint64_t file_size, std::size_t block_index) {
  std::uint64_t parts = (file_size + PART_SIZE - 1) / PART_SIZE;
  std::size_t remaining = block_index;
  for (std::uint64_t i = 0; i < parts; ++i) {
    std::uint64_t part_size = std::min(PART_SIZE, file_size - i * PART_SIZE);
    std::uint64_t bip = blocks_in_part(part_size);
    if (remaining < bip) {
      return i * PART_SIZE + static_cast<std::uint64_t>(remaining) * AICH_BLOCK_SIZE;
    }
    remaining -= static_cast<std::size_t>(bip);
  }
  return file_size;  // 越界（调用方已守卫）
}

std::uint64_t total_blocks(std::uint64_t file_size) {
  if (file_size == 0) return 0;
  std::uint64_t parts = (file_size + PART_SIZE - 1) / PART_SIZE;
  std::uint64_t total = 0;
  for (std::uint64_t i = 0; i < parts; ++i) {
    std::uint64_t part_size = std::min(PART_SIZE, file_size - i * PART_SIZE);
    total += blocks_in_part(part_size);
  }
  return total;
}

// 从子树根递归到 target_off 处的叶，沿路径向上归并出子树根 hash；消费 proof（bottom-up）。
// data_size/base/is_left 描述当前子树；leaf_hash 为目标叶 SHA1（叶处直接返回）。
// 两级树为真二叉树（nBlocks>=2 时左右子各 >=1 叶），无 lone-child；proof 不足返回 nullopt。
std::optional<Digest> walk(std::uint64_t data_size, std::uint64_t base, bool is_left,
                           std::uint64_t target_off, const Digest& leaf_hash,
                           std::span<const Digest> proof, std::size_t& pi) {
  if (data_size <= base) {
    return leaf_hash;  // 叶：data_size <= base，单块即此叶
  }
  std::uint64_t nBlocks = data_size / base + ((data_size % base != 0) ? 1 : 0);
  std::uint64_t nLeft = ((is_left ? nBlocks + 1 : nBlocks) / 2) * base;
  std::uint64_t nRight = data_size - nLeft;
  std::uint64_t base_left = (nLeft <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE;
  std::uint64_t base_right = (nRight <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE;
  if (target_off < nLeft) {
    auto L = walk(nLeft, base_left, true, target_off, leaf_hash, proof, pi);
    if (!L) return std::nullopt;
    if (nRight > 0) {
      if (pi >= proof.size()) return std::nullopt;
      Digest R = proof[pi++];
      return sha1_cat(*L, R);
    }
    return L;  // 理论不达（nBlocks>=2 时 nRight>0）
  } else {
    auto R = walk(nRight, base_right, false, target_off - nLeft, leaf_hash, proof, pi);
    if (!R) return std::nullopt;
    if (pi >= proof.size()) return std::nullopt;
    Digest L = proof[pi++];
    return sha1_cat(L, *R);
  }
}
}  // namespace

AICHChecker::AICHChecker(AICHHash root_hash, std::uint64_t file_size)
    : root_(root_hash), file_size_(file_size),
      root_base_((file_size <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE) {}

bool AICHChecker::verify_block(std::size_t block_index, std::span<const std::byte> data,
                               std::span<const std::array<std::byte, 20>> proof_path) {
  if (file_size_ == 0) return false;
  if (block_index >= total_blocks(file_size_)) return false;
  crypto::SHA1 lh;
  lh.update(data);
  Digest leaf_hash = lh.finish();
  std::uint64_t off = target_offset(file_size_, block_index);
  std::size_t pi = 0;
  auto r = walk(file_size_, root_base_, true, off, leaf_hash, proof_path, pi);
  if (!r) return false;
  return pi == proof_path.size() && *r == root_.bytes();
}

}
