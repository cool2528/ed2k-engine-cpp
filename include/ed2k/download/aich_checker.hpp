#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <array>
#include "ed2k/core/hash.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/peer/c2c_messages.hpp"   // peer::AICHProofHash (V2 recovery data 项)
namespace ed2k::download {

// AICH 块级校验器（两级 Merkle 树，对照 aMule SHAHashSet）。
//   顶层 base = PART_SIZE（文件 > PART_SIZE 时），part 子树 base = AICH_BLOCK_SIZE。
//   分裂规则 nLeft = ((is_left?nBlocks+1:nBlocks)/2)*base（left-biased：左 ceil、右 floor）。
//   两级树为真二叉树（nBlocks>=2 时左右子各 >=1 叶），无 lone-child。
//
// verify_block(part_index, block_in_part, data, proof)（M4b）：
//   proof = V2 recovery data = (nLevel-1) 兄弟 part-root + 该 part 全部 L 叶, 每项含 MSB-first
//   标识符(aMule WriteHash/WriteLowestLevelHashs, 与 SetHash 解码一致)。两步安全验证：
//     (1) leaf: SHA1(block_data) == proof 中 block 对应叶的 hash (块数据完整性);
//     (2) root: 按 part 叶重建 part-root → 沿顶层树与兄弟 part-root 归并到 file root → == master
//              (证明数据对受信 master 的绑定的校验, SHA1 原像不可行 → 抗恶意 peer)。
//   标识符为根→叶 MSB-first 路径: 左子=(ident<<1)|1, 右子=ident<<1; 根 ident=1 (=master, 不入 proof)。
class AICHChecker {
 public:
  AICHChecker(AICHHash root_hash, std::uint64_t file_size);
  bool verify_block(std::size_t part_index, std::size_t block_in_part,
                    std::span<const std::byte> data,
                    std::span<const peer::AICHProofHash> proof);
 private:
  AICHHash root_;
  std::uint64_t file_size_;
  std::uint64_t root_base_;   // (file_size <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE
};

}
