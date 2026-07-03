#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <array>
#include "ed2k/core/hash.hpp"
#include "ed2k/hash/aich_hasher.hpp"
namespace ed2k::download {

// AICH 块级校验器（两级 Merkle 树，对照 aMule SHAHashSet）。
//   顶层 base = PART_SIZE（文件 > PART_SIZE 时），part 子树 base = AICH_BLOCK_SIZE。
//   分裂规则 nLeft = ((is_left?nBlocks+1:nBlocks)/2)*base（left-biased：左 ceil、右 floor）。
//   两级树为真二叉树（nBlocks>=2 时左右子各 >=1 叶），无 lone-child。
// verify_block 的 block_index 为两级叶序号（part*blocks_per_part + block_in_part），
// 与 aich_hash_bytes 的叶序一致。download 侧 flat 块模型在 M4 per-part 落地前对多 part
// 文件与此序号不一致——见 impl-plan G11（download AICH 用例 DISABLED 待 M4）。
class AICHChecker {
 public:
  AICHChecker(AICHHash root_hash, std::uint64_t file_size);
  // Verify a block: leaf data + bottom-up sibling proof path from peer -> true = ok.
  // block_index: two-level leaf index (part-major). proof: ordered siblings leaf→root.
  bool verify_block(std::size_t block_index, std::span<const std::byte> data,
                    std::span<const std::array<std::byte, 20>> proof_path);
 private:
  AICHHash root_;
  std::uint64_t file_size_;
  std::uint64_t root_base_;   // (file_size <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE
};

}
