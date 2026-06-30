#include "ed2k/download/aich_checker.hpp"
#include "ed2k/crypto/sha1.hpp"

namespace ed2k::download {

AICHChecker::AICHChecker(AICHHash root_hash, std::size_t num_blocks)
  : root_(root_hash), num_blocks_(num_blocks) {}

bool AICHChecker::verify_block(std::size_t global_block_index, std::span<const std::byte> data,
                               std::span<const std::array<std::byte, 20>> proof_path) {
  // hash the block data
  crypto::SHA1 hasher;
  hasher.update(data);
  auto leaf_hash = hasher.finish();

  // walk up the tree with the proof path
  std::array<std::byte, 20> current = leaf_hash;
  std::size_t index = global_block_index;
  for (auto sibling : proof_path) {
    // hash combined with sibling depending on parity
    crypto::SHA1 hasher_up;
    if (index % 2 == 0) {
      // current is left, sibling is right
      hasher_up.update(current);
      hasher_up.update(sibling);
    } else {
      // current is right, sibling is left
      hasher_up.update(sibling);
      hasher_up.update(current);
    }
    current = hasher_up.finish();
    index /= 2;
  }

  // compare with root
  return current == root_.bytes();
}

}
