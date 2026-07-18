#include "ed2k/download/aich_checker.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/crypto/sha1.hpp"
#include <optional>
#include <unordered_map>
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

// 左偏分裂 (aMule SHAHashSet.cpp:118-119/294-296):
//   nLeft = ((is_left?nBlocks+1:nBlocks)/2)*base, nRight = data_size-nLeft
//   子节点 base = (nSide<=PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE  (nLeft==PART_SIZE → AICH_BLOCK_SIZE)
struct Split { std::uint64_t n_left, n_right, base_left, base_right; };
Split split_children(std::uint64_t data_size, std::uint64_t base, bool is_left) {
  std::uint64_t nBlocks = data_size / base + ((data_size % base != 0) ? 1 : 0);
  std::uint64_t nLeft = ((is_left ? nBlocks + 1 : nBlocks) / 2) * base;
  std::uint64_t nRight = data_size - nLeft;
  std::uint64_t bl = (nLeft  <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE;
  std::uint64_t br = (nRight <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE;
  return {nLeft, nRight, bl, br};
}

// 递归重建 file root (aMule ReCalculateHash 的对偶, 按树结构 + 提供的 hash):
//   ident = 当前节点标识符 (根=1; 左子=(ident<<1)|1, 右子=ident<<1)。
//   - ident!=1 且 map 含 ident: 用提供的 hash (叶或兄弟 part-root 子树根; 安全性由 root 校验保证)。
//   - data_size<=base 且未提供: 缺叶 → nullopt (证明不完整)。
//   - 否则: 递归左右子, SHA1(L||R) 归并 (内部节点, 如 part-root / 顶层内部, 不在 proof 中 → 重建)。
std::optional<Digest> rebuild(std::uint64_t data_size, std::uint64_t base, bool is_left,
                              std::uint32_t ident,
                              const std::unordered_map<std::uint32_t, Digest>& m) {
  if (ident != 1) {
    auto it = m.find(ident);
    if (it != m.end()) return it->second;   // 提供的叶 / 兄弟 part-root
  }
  if (data_size <= base) return std::nullopt;   // 叶级节点未提供 → 证明缺失
  auto s = split_children(data_size, base, is_left);
  auto L = rebuild(s.n_left, s.base_left, true, (ident << 1) | 1, m);
  if (!L) return std::nullopt;
  auto R = rebuild(s.n_right, s.base_right, false, ident << 1, m);
  if (!R) return std::nullopt;
  return sha1_cat(*L, *R);
}

// 计算 (part_index, block_in_part) 对应叶的标识符 (根→叶 MSB-first 路径, 与 rebuild/WriteLowestLevelHashs 同构)。
std::uint32_t leaf_ident(std::uint64_t data_size, std::uint64_t base, bool is_left,
                         std::uint64_t target_off, std::uint32_t ident) {
  if (data_size <= base) return ident;
  auto s = split_children(data_size, base, is_left);
  if (target_off < s.n_left) {
    return leaf_ident(s.n_left, s.base_left, true, target_off, (ident << 1) | 1);
  }
  return leaf_ident(s.n_right, s.base_right, false, target_off - s.n_left, ident << 1);
}
}  // namespace

AICHChecker::AICHChecker(AICHHash root_hash, std::uint64_t file_size)
    : root_(root_hash), file_size_(file_size),
      root_base_((file_size <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE) {}

bool AICHChecker::verify_block(std::size_t part_index, std::size_t block_in_part,
                               std::span<const std::byte> data,
                               std::span<const peer::AICHProofHash> proof) {
  if (file_size_ == 0) return false;
  // 范围检查
  std::uint64_t nparts = (file_size_ + PART_SIZE - 1) / PART_SIZE;
  if (part_index >= nparts) return false;
  std::uint64_t pstart = static_cast<std::uint64_t>(part_index) * PART_SIZE;
  std::uint64_t psize = std::min(PART_SIZE, file_size_ - pstart);
  std::uint64_t blocks_in_p = (psize + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;
  if (block_in_part >= blocks_in_p) return false;

  // 建 ident->hash map (排除 ident==1 = master; aMule ReadRecoveryData 亦拒 ident 1)
  std::unordered_map<std::uint32_t, Digest> m;
  m.reserve(proof.size());
  for (const auto& p : proof) {
    if (p.identifier == 1) continue;
    m.emplace(p.identifier, p.hash);
  }

  // (1) leaf 校验: SHA1(block_data) == 该 block 叶的 hash (块数据完整性)
  std::uint64_t target_off = pstart + static_cast<std::uint64_t>(block_in_part) * AICH_BLOCK_SIZE;
  std::uint32_t lid = leaf_ident(file_size_, root_base_, true, target_off, 1);
  crypto::SHA1 lh; lh.update(data); Digest leaf_hash = lh.finish();
  auto lit = m.find(lid);
  if (lit == m.end() || lit->second != leaf_hash) return false;

  // (2) root 重建校验: rebuild(file) == master (证明数据对受信 master 的绑定)
  auto r = rebuild(file_size_, root_base_, true, 1, m);
  if (!r) return false;
  return *r == root_.bytes();
}

}
