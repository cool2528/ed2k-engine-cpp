#include "ed2k/download/aich_checker.hpp"
#include "ed2k/crypto/sha1.hpp"

namespace ed2k::download {

AICHChecker::AICHChecker(AICHHash root_hash, std::size_t num_blocks)
  : root_(root_hash), num_blocks_(num_blocks) {}

bool AICHChecker::verify_block(std::size_t global_block_index, std::span<const std::byte> data,
                               std::span<const std::array<std::byte, 20>> proof_path) {
  if (global_block_index >= num_blocks_) return false;
  crypto::SHA1 hasher;
  hasher.update(data);
  std::array<std::byte, 20> current = hasher.finish();

  std::size_t index = global_block_index;
  std::size_t level_size = num_blocks_;
  std::size_t pi = 0;   // proof_path 消费指针
  while (level_size > 1) {
    std::size_t sib = index ^ 1;   // 偶→右邻, 奇→左邻
    if (sib < level_size) {
      // 有 sibling: combine 一次, 消费 proof 一项
      if (pi >= proof_path.size()) return false;   // proof 短缺
      crypto::SHA1 up;
      if (index % 2 == 0) { up.update(current); up.update(proof_path[pi]); }
      else                { up.update(proof_path[pi]); up.update(current); }
      current = up.finish();
      ++pi;
    }
    // else lone-child: 无 sibling, current 直接上提, 不消费 proof
    level_size = (level_size + 1) / 2;
    index /= 2;
  }
  return (pi == proof_path.size()) && (current == root_.bytes());
}

}
