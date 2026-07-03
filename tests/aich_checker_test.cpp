#include <gtest/gtest.h>
#include "ed2k/download/aich_checker.hpp"
#include "ed2k/hash/aich_hasher.hpp"   // ed2k::AICH_BLOCK_SIZE, ed2k::PART_SIZE
#include "ed2k/peer/c2c_messages.hpp"  // peer::AICHProofHash
#include "ed2k/crypto/sha1.hpp"
#include <vector>
#include <cstdint>
#include <algorithm>
using namespace ed2k; using namespace ed2k::download;
using ed2k::peer::AICHProofHash;

namespace {
using Digest = std::array<std::byte, 20>;

Digest cat(const Digest& l, const Digest& r) {
  crypto::SHA1 h; h.update(l); h.update(r); return h.finish();
}

struct Split { std::uint64_t n_left, n_right, base_left, base_right; };
Split split_children(std::uint64_t n, std::uint64_t base, bool is_left) {
  std::uint64_t nBlocks = n / base + ((n % base) != 0 ? 1 : 0);
  std::uint64_t nLeft = ((is_left ? nBlocks + 1 : nBlocks) / 2) * base;
  std::uint64_t nRight = n - nLeft;
  std::uint64_t bl = (nLeft  <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  std::uint64_t br = (nRight <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  return {nLeft, nRight, bl, br};
}

// 子树根（aich_hasher build_subtree 的独立复刻，交叉校验 + 兄弟 part-root hash 用）。对照 aMule SHAHashSet。
Digest subtree_root(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left) {
  if (n <= base) return crypto::sha1(d.first(static_cast<std::size_t>(n)));
  auto s = split_children(n, base, is_left);
  return cat(subtree_root(d.first(static_cast<std::size_t>(s.n_left)),  s.n_left,  s.base_left,  true),
             subtree_root(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false));
}

// WriteLowestLevelHashs 对偶: 收集子树所有叶 (ident, SHA1(叶数据)), 左→右序。
//   ident = 当前节点标识符 (左子=(ident<<1)|1, 右子=ident<<1)。
void collect_leaves(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left,
                    std::uint32_t ident, std::vector<AICHProofHash>& out) {
  if (n <= base) {
    AICHProofHash p; p.identifier = ident; p.hash = crypto::sha1(d.first(static_cast<std::size_t>(n)));
    out.push_back(p); return;
  }
  auto s = split_children(n, base, is_left);
  collect_leaves(d.first(static_cast<std::size_t>(s.n_left)),  s.n_left,  s.base_left,  true,  (ident << 1) | 1, out);
  collect_leaves(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false, ident << 1,       out);
}

// CreatePartRecoveryData 对偶: 收集 part 的 V2 恢复数据 = (nLevel-1) 兄弟 part-root + 该 part 全部 L 叶。
//   ident = 当前节点标识符; part_off/part_size = part 在当前节点数据内的 [偏移, 大小)。
void collect_recovery(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left,
                      std::uint32_t ident, std::uint64_t part_off, std::uint64_t part_size,
                      std::vector<AICHProofHash>& out) {
  if (part_off == 0 && part_size == n) {
    collect_leaves(d, n, base, is_left, ident, out);   // 当前节点即 part root → 收集所有叶
    return;
  }
  auto s = split_children(n, base, is_left);
  std::uint32_t left_ident = (ident << 1) | 1, right_ident = ident << 1;
  if (part_off < s.n_left) {
    AICHProofHash p; p.identifier = right_ident;
    p.hash = subtree_root(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false);
    out.push_back(p);
    collect_recovery(d.first(static_cast<std::size_t>(s.n_left)), s.n_left, s.base_left, true,
                     left_ident, part_off, part_size, out);
  } else {
    AICHProofHash p; p.identifier = left_ident;
    p.hash = subtree_root(d.first(static_cast<std::size_t>(s.n_left)), s.n_left, s.base_left, true);
    out.push_back(p);
    collect_recovery(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false,
                     right_ident, part_off - s.n_left, part_size, out);
  }
}

// 生成 part 的 V2 恢复数据 (对照 aMule CAICHHashSet::CreatePartRecoveryData)。
std::vector<AICHProofHash> recovery_for(const std::vector<std::byte>& full, std::size_t part_index) {
  std::uint64_t n = full.size();
  std::uint64_t root_base = (n <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  std::uint64_t pstart = static_cast<std::uint64_t>(part_index) * PART_SIZE;
  std::uint64_t psize = std::min(PART_SIZE, n - pstart);
  std::vector<AICHProofHash> out;
  collect_recovery(std::span<const std::byte>(full), n, root_base, true, 1, pstart, psize, out);
  return out;
}

// 取 (part_index, block_in_part) 块的字节区 (含末块短块)。
std::span<const std::byte> block_span(const std::vector<std::byte>& full,
                                      std::size_t part_index, std::size_t block_in_part) {
  std::uint64_t n = full.size();
  std::uint64_t pstart = static_cast<std::uint64_t>(part_index) * PART_SIZE;
  std::uint64_t psize = std::min(PART_SIZE, n - pstart);
  std::uint64_t off = pstart + static_cast<std::uint64_t>(block_in_part) * AICH_BLOCK_SIZE;
  std::uint64_t blk_size = std::min(static_cast<std::uint64_t>(AICH_BLOCK_SIZE), pstart + psize - off);
  return std::span<const std::byte>(full).subspan(static_cast<std::size_t>(off),
                                                   static_cast<std::size_t>(blk_size));
}
}  // namespace

TEST(AICHChecker, VerifyGoodBlockSucceeds) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x11));   // 1 part, 2 blocks
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto rec = recovery_for(data, 0);
  EXPECT_TRUE(checker.verify_block(0, 0, block_span(data, 0, 0), rec));
}

TEST(AICHChecker, VerifyBadBlockFails) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x11));
  auto hash = aich_hash_bytes(data);          // clean master
  AICHChecker checker{hash, data.size()};
  auto rec = recovery_for(data, 0);           // clean recovery (computed before corruption)
  data[0] = std::byte(0xFF);                  // corrupt block 0 data
  EXPECT_FALSE(checker.verify_block(0, 0, block_span(data, 0, 0), rec));   // SHA1(data) != leaf
}

TEST(AICHChecker, VerifyRightChildBlockSucceeds) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x33));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto rec = recovery_for(data, 0);
  EXPECT_TRUE(checker.verify_block(0, 1, block_span(data, 0, 1), rec));   // 右叶
}

TEST(AICHChecker, VerifyLoneLastBlockSucceeds) {
  // 3 块单 part: 两级 split 2|1, block 2 在右子树单叶。
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 3, std::byte(0x55));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto rec = recovery_for(data, 0);
  EXPECT_TRUE(checker.verify_block(0, 2, block_span(data, 0, 2), rec));
}

TEST(AICHChecker, VerifyTamperedLeafFails) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x33));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto rec = recovery_for(data, 0);
  ASSERT_FALSE(rec.empty());
  rec[0].hash[0] = rec[0].hash[0] ^ std::byte(0x01);   // 篡改某叶 hash
  EXPECT_FALSE(checker.verify_block(0, 0, block_span(data, 0, 0), rec));
}

TEST(AICHChecker, VerifyShortProofFails) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x33));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  std::vector<AICHProofHash> empty;           // 空 recovery → 叶缺失
  EXPECT_FALSE(checker.verify_block(0, 0, block_span(data, 0, 0), empty));
}

TEST(AICHChecker, VerifyWrongMasterFails) {
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x33));
  auto rec = recovery_for(data, 0);
  Digest bad; bad.fill(std::byte(0xAA));
  AICHChecker checker{AICHHash::from_bytes(bad), data.size()};   // 错误 master
  EXPECT_FALSE(checker.verify_block(0, 0, block_span(data, 0, 0), rec));   // rebuild != bad master
}

TEST(AICHChecker, VerifyMissingLeafFails) {
  // 漏掉 block 0 的叶 (ident 3) → 叶缺失, rebuild 亦缺该叶
  std::vector<std::byte> data(AICH_BLOCK_SIZE * 2, std::byte(0x33));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, data.size()};
  auto rec = recovery_for(data, 0);
  auto it = std::find_if(rec.begin(), rec.end(),
                         [](const AICHProofHash& p){ return p.identifier == 3; });
  ASSERT_TRUE(it != rec.end());
  rec.erase(it);
  EXPECT_FALSE(checker.verify_block(0, 0, block_span(data, 0, 0), rec));
}

TEST(AICHChecker, MultiPartProofPath) {
  // 2-part 文件: part0=PART(53 块末短 143360B)、part1=2*EB(2 块)。
  // 验证 part0 首/末块与 part1 块(顶层右子树 + part1 子树, 深度>1)。
  std::uint64_t fs = PART_SIZE + 2 * AICH_BLOCK_SIZE;
  std::vector<std::byte> data(static_cast<std::size_t>(fs), std::byte(0x77));
  auto hash = aich_hash_bytes(data);
  AICHChecker checker{hash, fs};
  EXPECT_TRUE(checker.verify_block(0, 0,  block_span(data, 0, 0),  recovery_for(data, 0)));
  EXPECT_TRUE(checker.verify_block(0, 52, block_span(data, 0, 52), recovery_for(data, 0)));
  EXPECT_TRUE(checker.verify_block(1, 0,  block_span(data, 1, 0),  recovery_for(data, 1)));
  EXPECT_TRUE(checker.verify_block(1, 1,  block_span(data, 1, 1),  recovery_for(data, 1)));
  // 篡改 part1 recovery 的顶层 sibling(part0 root @ ident 3) → rebuild != master
  auto rec = recovery_for(data, 1);
  auto it = std::find_if(rec.begin(), rec.end(),
                         [](const AICHProofHash& p){ return p.identifier == 3; });
  ASSERT_TRUE(it != rec.end());
  it->hash[0] = it->hash[0] ^ std::byte(0x01);
  EXPECT_FALSE(checker.verify_block(1, 0, block_span(data, 1, 0), rec));
  // 越界 part / block_in_part → 失败
  EXPECT_FALSE(checker.verify_block(2, 0, block_span(data, 1, 1), recovery_for(data, 1)));
  EXPECT_FALSE(checker.verify_block(1, 2, block_span(data, 1, 1), recovery_for(data, 1)));
}
