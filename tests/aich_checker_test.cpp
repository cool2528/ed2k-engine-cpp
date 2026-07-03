#include <gtest/gtest.h>
#include "ed2k/download/aich_checker.hpp"
#include "ed2k/hash/aich_hasher.hpp"   // ed2k::AICH_BLOCK_SIZE, ed2k::PART_SIZE
#include "ed2k/crypto/sha1.hpp"
#include <vector>
#include <cstdint>
#include <algorithm>
using namespace ed2k; using namespace ed2k::download;

namespace {
using Digest = std::array<std::byte, 20>;

Digest cat(const Digest& l, const Digest& r) {
  crypto::SHA1 h; h.update(l); h.update(r); return h.finish();
}

// 子树根（aich_hasher build_subtree 的独立复刻，交叉校验用）。对照 aMule SHAHashSet。
Digest subtree_root(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left) {
  if (n <= base) return crypto::sha1(d.first(static_cast<std::size_t>(n)));
  std::uint64_t nBlocks = n / base + ((n % base) != 0 ? 1 : 0);
  std::uint64_t nLeft = ((is_left ? nBlocks + 1 : nBlocks) / 2) * base;
  std::uint64_t nRight = n - nLeft;
  std::uint64_t bl = (nLeft  <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  std::uint64_t br = (nRight <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  return cat(subtree_root(d.first(static_cast<std::size_t>(nLeft)),  nLeft,  bl, true),
             subtree_root(d.subspan(static_cast<std::size_t>(nLeft)), nRight, br, false));
}

std::uint64_t blocks_in_part(std::uint64_t part_size) {
  return (part_size + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;
}
// 两级叶序（part-major）→ 目标块字节偏移（与 aich_checker.cpp::target_offset 同构）。
std::uint64_t tgt_offset(std::uint64_t file_size, std::size_t block_index) {
  std::uint64_t parts = (file_size + PART_SIZE - 1) / PART_SIZE;
  std::size_t rem = block_index;
  for (std::uint64_t i = 0; i < parts; ++i) {
    std::uint64_t ps = std::min(PART_SIZE, file_size - i * PART_SIZE);
    std::uint64_t bip = blocks_in_part(ps);
    if (rem < bip) return i * PART_SIZE + static_cast<std::uint64_t>(rem) * AICH_BLOCK_SIZE;
    rem -= static_cast<std::size_t>(bip);
  }
  return file_size;
}

// 两级 proof（bottom-up：叶→root 的 sibling 子树根序，与 verify_block::walk 消费序一致）。
std::vector<Digest> proof_gen(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base,
                              bool is_left, std::uint64_t target_off) {
  if (n <= base) return {};
  std::uint64_t nBlocks = n / base + ((n % base) != 0 ? 1 : 0);
  std::uint64_t nLeft = ((is_left ? nBlocks + 1 : nBlocks) / 2) * base;
  std::uint64_t nRight = n - nLeft;
  std::uint64_t bl = (nLeft  <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  std::uint64_t br = (nRight <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  if (target_off < nLeft) {
    auto p = proof_gen(d.first(static_cast<std::size_t>(nLeft)), nLeft, bl, true, target_off);
    if (nRight > 0) p.push_back(subtree_root(d.subspan(static_cast<std::size_t>(nLeft)), nRight, br, false));
    return p;
  } else {
    auto p = proof_gen(d.subspan(static_cast<std::size_t>(nLeft)), nRight, br, false, target_off - nLeft);
    p.push_back(subtree_root(d.first(static_cast<std::size_t>(nLeft)), nLeft, bl, true));
    return p;
  }
}

std::vector<Digest> proof_for(const std::vector<std::byte>& full, std::size_t block_index) {
  std::uint64_t n = full.size();
  std::uint64_t root_base = (n <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  return proof_gen(std::span<const std::byte>(full), n, root_base, true, tgt_offset(n, block_index));
}

// 取两级第 block_index 块的字节区（含末块短块）。
std::span<const std::byte> block_span(const std::vector<std::byte>& full, std::size_t block_index) {
  std::uint64_t n = full.size();
  std::uint64_t off = tgt_offset(n, block_index);
  std::uint64_t part = off / PART_SIZE;
  std::uint64_t part_size = std::min(PART_SIZE, n - part * PART_SIZE);
  std::uint64_t blk_in_part = (off % PART_SIZE) / AICH_BLOCK_SIZE;
  std::uint64_t blk_size = std::min(static_cast<std::uint64_t>(AICH_BLOCK_SIZE),
                                    part_size - blk_in_part * AICH_BLOCK_SIZE);
  return std::span<const std::byte>(full).subspan(static_cast<std::size_t>(off),
                                                   static_cast<std::size_t>(blk_size));
}
}  // namespace

TEST(AICHChecker, VerifyGoodBlockSucceeds) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x11));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto path = proof_for(data, 0);
  EXPECT_TRUE(checker.verify_block(0, block_span(data, 0), path));
}

TEST(AICHChecker, VerifyBadBlockFails) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x11));
  auto hash = aich_hash_bytes(data);          // clean root
  AICHChecker checker{hash, data.size()};
  auto path = proof_for(data, 0);             // clean proof (computed before corruption)
  data[0] = std::byte(0xFF);                  // corrupt block 0
  EXPECT_FALSE(checker.verify_block(0, block_span(data, 0), path));
}

TEST(AICHChecker, VerifyRightChildBlockSucceeds) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x33));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto path = proof_for(data, 1);             // 右叶
  EXPECT_TRUE(checker.verify_block(1, block_span(data, 1), path));
}

TEST(AICHChecker, VerifyLoneLastBlockSucceeds) {
  // 3 块单 part：两级 split 2|1，block 2 在右子树（单叶）。
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 3, std::byte(0x55));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto path = proof_for(data, 2);
  EXPECT_TRUE(checker.verify_block(2, block_span(data, 2), path));
}

TEST(AICHChecker, VerifyCorruptDataFails) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x33));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto path = proof_for(data, 0);
  data[0] = std::byte(0xFF);
  EXPECT_FALSE(checker.verify_block(0, block_span(data, 0), path));
}

TEST(AICHChecker, VerifyTamperedProofFails) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x33));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto path = proof_for(data, 0);
  path[0][0] = path[0][0] ^ std::byte(0x01);   // 篡改 proof
  EXPECT_FALSE(checker.verify_block(0, block_span(data, 0), path));
}

TEST(AICHChecker, VerifyShortProofFails) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x33));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  std::vector<Digest> short_path;              // 空 proof, 应不足
  EXPECT_FALSE(checker.verify_block(0, block_span(data, 0), short_path));
}

TEST(AICHChecker, VerifyExtraProofFails) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x33));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto path = proof_for(data, 0);
  Digest extra = crypto::sha1(std::span<const std::byte>(data).first(AICH_BLOCK_SIZE));
  path.push_back(extra);                       // 多余 proof
  EXPECT_FALSE(checker.verify_block(0, block_span(data, 0), path));
}

TEST(AICHChecker, MultiPartProofPath) {
  // 2-part 文件：part0=PART(53 块，末块 143360B)、part1=2*EB(2 块)。
  // 验证 part0 首/末块与 part1 块（顶层右子树 + part1 子树），两级 proof path 深度>1。
  std::uint64_t fs = PART_SIZE + 2 * AICH_BLOCK_SIZE;
  std::vector<std::byte> data(static_cast<std::size_t>(fs), std::byte(0x77));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, fs};
  for (std::size_t idx : {std::size_t{0}, std::size_t{52},   // part0 首块、末短块
                          std::size_t{53}, std::size_t{54}}) { // part1 块（顶层右子树）
    auto path = proof_for(data, idx);
    EXPECT_TRUE(checker.verify_block(idx, block_span(data, idx), path)) << "block " << idx;
  }
  // 篡改 part1 块 proof 的顶层 sibling（part0 root）→ 校验失败
  auto path = proof_for(data, 53);
  path.back()[0] = path.back()[0] ^ std::byte(0x01);
  EXPECT_FALSE(checker.verify_block(53, block_span(data, 53), path));
  // 块索引越界 → 失败
  EXPECT_FALSE(checker.verify_block(55, block_span(data, 54), proof_for(data, 54)));
}
