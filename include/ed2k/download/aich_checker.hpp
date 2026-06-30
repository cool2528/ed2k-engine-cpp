#pragma once
#include <cstddef>
#include <span>
#include <array>
#include "ed2k/core/hash.hpp"
#include "ed2k/hash/aich_hasher.hpp"
namespace ed2k::download {

class AICHChecker {
 public:
  AICHChecker(AICHHash root_hash, std::size_t num_blocks);
  // Verify a block: data + hash proof path from peer -> true = ok
  bool verify_block(std::size_t global_block_index, std::span<const std::byte> data,
                    std::span<const std::array<std::byte, 20>> proof_path);
 private:
  AICHHash root_;
  std::size_t num_blocks_;
};

}
