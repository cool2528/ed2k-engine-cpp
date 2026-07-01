#include <gtest/gtest.h>
#include "ed2k/download/aich_checker.hpp"
#include "ed2k/hash/aich_hasher.hpp"   // ed2k::AICH_BLOCK_SIZE
#include "ed2k/crypto/sha1.hpp"
#include <vector>
using namespace ed2k; using namespace ed2k::download;

namespace {
using Digest = std::array<std::byte, 20>;

std::vector<Digest> compute_proof_path(std::size_t block_index, std::vector<Digest> leaves) {
  std::vector<Digest> path;
  std::size_t index = block_index;
  while (leaves.size() > 1) {
    std::size_t sibling = (index % 2 == 0) ? (index + 1) : (index - 1);
    if (sibling < leaves.size()) {
      path.push_back(leaves[sibling]);
    }
    std::vector<Digest> next;
    for (std::size_t i = 0; i < leaves.size(); i += 2) {
      if (i + 1 < leaves.size()) {
        // hash the concatenation of the two digests
        crypto::SHA1 hasher;
        hasher.update(leaves[i]);
        hasher.update(leaves[i+1]);
        next.push_back(hasher.finish());
      } else {
        next.push_back(leaves[i]);
      }
    }
    leaves.swap(next);
    index /= 2;
  }
  return path;
}
}

TEST(AICHChecker, VerifyGoodBlockSucceeds){
  // compute full AICH hash for a small file: 2 blocks
  std::vector<std::byte> data;
  data.resize(AICH_BLOCK_SIZE * 2, std::byte(0x11));

  // compute leaf hashes manually
  std::vector<std::array<std::byte, 20>> leaves;
  {
    crypto::SHA1 h0;
    h0.update(std::span(data).subspan(0, AICH_BLOCK_SIZE));
    leaves.push_back(h0.finish());
    crypto::SHA1 h1;
    h1.update(std::span(data).subspan(AICH_BLOCK_SIZE));
    leaves.push_back(h1.finish());
  }

  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, leaves.size()};
  auto path = compute_proof_path(0, leaves);
  EXPECT_TRUE(checker.verify_block(0, std::span(data).subspan(0, AICH_BLOCK_SIZE), path));
}

TEST(AICHChecker, VerifyBadBlockFails){
  // compute full AICH hash for a small file: 2 blocks
  std::vector<std::byte> data;
  data.resize(AICH_BLOCK_SIZE * 2, std::byte(0x11));

  // compute leaf hashes manually
  std::vector<std::array<std::byte, 20>> leaves;
  {
    crypto::SHA1 h0;
    h0.update(std::span(data).subspan(0, AICH_BLOCK_SIZE));
    leaves.push_back(h0.finish());
    crypto::SHA1 h1;
    h1.update(std::span(data).subspan(AICH_BLOCK_SIZE));
    leaves.push_back(h1.finish());
  }

  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, leaves.size()};
  data[0] = std::byte(0xFF); // corrupt first block
  auto path = compute_proof_path(0, leaves);
  EXPECT_FALSE(checker.verify_block(0, std::span(data).subspan(0, AICH_BLOCK_SIZE), path));
}

TEST(AICHChecker, VerifyRightChildBlockSucceeds){
  std::vector<std::byte> data(AICH_BLOCK_SIZE*2, std::byte(0x33));
  std::vector<std::array<std::byte,20>> leaves;
  leaves.push_back(crypto::sha1(std::span(data).subspan(0,AICH_BLOCK_SIZE)));
  leaves.push_back(crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE,AICH_BLOCK_SIZE)));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, leaves.size()};
  auto path = compute_proof_path(1, leaves);   // 右叶(block_index=1)
  EXPECT_TRUE(checker.verify_block(1, std::span(data).subspan(AICH_BLOCK_SIZE,AICH_BLOCK_SIZE), path));
}

TEST(AICHChecker, VerifyLoneLastBlockSucceeds){
  // 3 块, 末位 lone(block_index=2)
  std::vector<std::byte> data(AICH_BLOCK_SIZE*3, std::byte(0x55));
  std::vector<std::array<std::byte,20>> leaves;
  for(int i=0;i<3;++i) leaves.push_back(crypto::sha1(std::span(data).subspan(i*AICH_BLOCK_SIZE,AICH_BLOCK_SIZE)));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, leaves.size()};
  auto path = compute_proof_path(2, leaves);
  EXPECT_TRUE(checker.verify_block(2, std::span(data).subspan(AICH_BLOCK_SIZE*2,AICH_BLOCK_SIZE), path));
}

TEST(AICHChecker, VerifyCorruptDataFails){
  std::vector<std::byte> data(AICH_BLOCK_SIZE*2, std::byte(0x33));
  std::vector<std::array<std::byte,20>> leaves;
  leaves.push_back(crypto::sha1(std::span(data).subspan(0,AICH_BLOCK_SIZE)));
  leaves.push_back(crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE,AICH_BLOCK_SIZE)));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, leaves.size()};
  data[0] = std::byte(0xFF);
  auto path = compute_proof_path(0, leaves);
  EXPECT_FALSE(checker.verify_block(0, std::span(data).subspan(0,AICH_BLOCK_SIZE), path));
}

TEST(AICHChecker, VerifyTamperedProofFails){
  std::vector<std::byte> data(AICH_BLOCK_SIZE*2, std::byte(0x33));
  std::vector<std::array<std::byte,20>> leaves;
  leaves.push_back(crypto::sha1(std::span(data).subspan(0,AICH_BLOCK_SIZE)));
  leaves.push_back(crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE,AICH_BLOCK_SIZE)));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, leaves.size()};
  auto path = compute_proof_path(0, leaves);
  path[0][0] = path[0][0] ^ std::byte(0x01);   // 篡改 proof
  EXPECT_FALSE(checker.verify_block(0, std::span(data).subspan(0,AICH_BLOCK_SIZE), path));
}

TEST(AICHChecker, VerifyShortProofFails){
  std::vector<std::byte> data(AICH_BLOCK_SIZE*2, std::byte(0x33));
  std::vector<std::array<std::byte,20>> leaves;
  leaves.push_back(crypto::sha1(std::span(data).subspan(0,AICH_BLOCK_SIZE)));
  leaves.push_back(crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE,AICH_BLOCK_SIZE)));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, leaves.size()};
  std::vector<std::array<std::byte,20>> short_path;   // 空 proof, 应不足
  EXPECT_FALSE(checker.verify_block(0, std::span(data).subspan(0,AICH_BLOCK_SIZE), short_path));
}

TEST(AICHChecker, VerifyExtraProofFails){
  std::vector<std::byte> data(AICH_BLOCK_SIZE*2, std::byte(0x33));
  std::vector<std::array<std::byte,20>> leaves;
  leaves.push_back(crypto::sha1(std::span(data).subspan(0,AICH_BLOCK_SIZE)));
  leaves.push_back(crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE,AICH_BLOCK_SIZE)));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, leaves.size()};
  auto path = compute_proof_path(0, leaves);
  path.push_back(leaves[0]);   // 多余 proof
  EXPECT_FALSE(checker.verify_block(0, std::span(data).subspan(0,AICH_BLOCK_SIZE), path));
}
