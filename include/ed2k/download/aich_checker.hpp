#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <array>
#include "ed2k/core/hash.hpp"
#include "ed2k/hash/aich_hasher.hpp"
namespace ed2k::peer { struct AICHProofHash; }
namespace ed2k::download {

// AICH block-level verifier (two-level Merkle tree, matched against aMule SHAHashSet).
//   Top-level base = PART_SIZE (when file > PART_SIZE), part subtree base = AICH_BLOCK_SIZE.
//   Split rule: nLeft = ((is_left?nBlocks+1:nBlocks)/2)*base (left-biased: left ceil, right floor).
//   Two-level tree is a full binary tree (when nBlocks>=2, left and right children each have >=1 leaf), no lone-child.
//
// verify_block(part_index, block_in_part, data, proof) (M4b):
//   proof = V2 recovery data = (nLevel-1) sibling part-roots + all L leaves of that part, each with MSB-first
//   identifier (aMule WriteHash/WriteLowestLevelHashs, consistent with SetHash decoding). Two-step secure verification:
//     (1) leaf: SHA1(block_data) == hash of the corresponding leaf in proof (block data integrity);
//     (2) root: rebuild part-root from part leaves -> merge with sibling part-roots along top-level tree to file root -> == master
//              (verifies binding of data to trusted master; SHA1 preimage infeasible -> resistant to malicious peers).
//   Identifier is root->leaf MSB-first path: left child=(ident<<1)|1, right child=ident<<1; root ident=1 (=master, not in proof).
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
