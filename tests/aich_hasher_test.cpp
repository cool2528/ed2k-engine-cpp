#include <gtest/gtest.h>
#include <vector>
#include "ed2k/hash/aich_hasher.hpp"
#include "crypto/sha1.hpp"
using namespace ed2k;
static std::vector<std::byte> fill(std::size_t n,std::uint8_t v){ return std::vector<std::byte>(n,std::byte{v}); }
TEST(Aich, SingleBlockEqualsSha1OfData){
  // 文件 < 一个小块且 < 一个 chunk：单块、单 chunk → AICH 根 = SHA1(data)
  auto data=fill(1000,0x41);
  auto a=aich_hash_bytes(data);
  auto s=crypto::sha1(data);
  EXPECT_EQ(a.bytes(), s);
}
TEST(Aich, DeterministicAndStable){
  auto data=fill(AICH_BLOCK_SIZE*3+5, 0x5A);
  auto a1=aich_hash_bytes(data);
  auto a2=aich_hash_bytes(data);
  EXPECT_EQ(a1, a2);                 // 确定性
  EXPECT_EQ(a1.to_base32().size(), 32u);
}
TEST(Aich, DiffersFromPlainSha1WhenMultiBlock){
  auto data=fill(AICH_BLOCK_SIZE*2, 0x33);
  EXPECT_NE(aich_hash_bytes(data).bytes(), crypto::sha1(data)); // 多块走 Merkle
}
namespace {
// 独立参考实现：两级平衡二叉 Merkle（与 aich_hasher.cpp 的 build_subtree 分开编写以交叉校验）。
// 对照 aMule SHAHashSet FindHash + ReCalculateHash。真实 aMule 字节级对照留 R0-1 live。
using RDigest = std::array<std::byte,20>;
RDigest ref_cat(const RDigest& l, const RDigest& r){
  std::array<std::byte,40> b; for(int i=0;i<20;++i){b[i]=l[i];b[20+i]=r[i];}
  return crypto::sha1(b);
}
RDigest ref_build(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left){
  if(n <= base) return crypto::sha1(d.first(static_cast<std::size_t>(n)));
  std::uint64_t nBlocks = n/base + ((n%base)!=0?1:0);
  std::uint64_t nLeft   = ((is_left?nBlocks+1:nBlocks)/2)*base;
  std::uint64_t nRight  = n - nLeft;
  std::uint64_t bl = (nLeft  <= PART_SIZE)?static_cast<std::uint64_t>(AICH_BLOCK_SIZE):PART_SIZE;
  std::uint64_t br = (nRight <= PART_SIZE)?static_cast<std::uint64_t>(AICH_BLOCK_SIZE):PART_SIZE;
  auto L = ref_build(d.first(static_cast<std::size_t>(nLeft)),  nLeft,  bl, true);
  auto R = ref_build(d.subspan(static_cast<std::size_t>(nLeft)), nRight, br, false);
  return ref_cat(L, R);
}
RDigest ref_two_level(std::span<const std::byte> d){
  std::uint64_t n = d.size();
  if(n==0) return crypto::sha1({});
  std::uint64_t root_base = (n <= PART_SIZE)?static_cast<std::uint64_t>(AICH_BLOCK_SIZE):PART_SIZE;
  return ref_build(d, n, root_base, true);
}
} // namespace

TEST(Aich, TwoLevelThreeBlocksMatchesManual){
  // 3 块(<1 part)：两级根 = SHA1(SHA1(h0||h1) || h2)。
  // 注：3 块单 part 的两级 split 恰与旧扁平 lone-child 同根，故此用例兼作两级 left-biased(ceil) 锚点。
  std::vector<std::byte> data(AICH_BLOCK_SIZE*3, std::byte(0x77));
  auto h0 = crypto::sha1(std::span(data).subspan(0, AICH_BLOCK_SIZE));
  auto h1 = crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE, AICH_BLOCK_SIZE));
  auto h2 = crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE*2, AICH_BLOCK_SIZE));
  std::array<std::byte,40> ab; for(int i=0;i<20;++i){ab[i]=h0[i];ab[20+i]=h1[i];}
  auto L = crypto::sha1(ab);
  std::array<std::byte,40> rb; for(int i=0;i<20;++i){rb[i]=L[i];rb[20+i]=h2[i];}
  auto expected = crypto::sha1(rb);   // SHA1(SHA1(h0||h1) || h2)
  EXPECT_EQ(aich_hash_bytes(data).bytes(), expected);
  EXPECT_EQ(aich_hash_bytes(data).bytes(), ref_two_level(data));
}
TEST(Aich, TwoLevelFourBlocksMatchesManual){
  // 4 块(<1 part)：两级根 = SHA1(SHA1(h0||h1) || SHA1(h2||h3))，验证偶数 split 归并。
  std::vector<std::byte> data(AICH_BLOCK_SIZE*4, std::byte(0x66));
  auto h0 = crypto::sha1(std::span(data).subspan(0, AICH_BLOCK_SIZE));
  auto h1 = crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE, AICH_BLOCK_SIZE));
  auto h2 = crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE*2, AICH_BLOCK_SIZE));
  auto h3 = crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE*3, AICH_BLOCK_SIZE));
  std::array<std::byte,40> ab; for(int i=0;i<20;++i){ab[i]=h0[i];ab[20+i]=h1[i];}
  auto L = crypto::sha1(ab);
  std::array<std::byte,40> cd; for(int i=0;i<20;++i){cd[i]=h2[i];cd[20+i]=h3[i];}
  auto R = crypto::sha1(cd);
  std::array<std::byte,40> root; for(int i=0;i<20;++i){root[i]=L[i];root[20+i]=R[i];}
  EXPECT_EQ(aich_hash_bytes(data).bytes(), crypto::sha1(root));
  EXPECT_EQ(aich_hash_bytes(data).bytes(), ref_two_level(data));
}
TEST(Aich, TwoLevelMultiPartMatchesReference){
  // 跨 part 边界(>9728000)：两级按 part 重新切叶（part0 末叶 143360B 非 184320B），根与扁平必然不同。
  // 用独立参考实现 ref_two_level 交叉校验 aich_hash_bytes。
  // 2 part：9953280B = part0(53块)+part1(2块短)
  std::vector<std::byte> a(AICH_BLOCK_SIZE*54, std::byte(0x77));
  EXPECT_EQ(aich_hash_bytes(a).bytes(), ref_two_level(a));
  // 3 part：PART_SIZE*2+1000 = part0+part1(各53块)+part2(1000B) —— 顶层右子 floor split
  std::vector<std::byte> b(static_cast<std::size_t>(PART_SIZE*2 + 1000), std::byte(0xFF));
  EXPECT_EQ(aich_hash_bytes(b).bytes(), ref_two_level(b));
  // 两级与扁平确实不同（旧扁平 54 块 lone-child 根 ≠ 两级根）
  std::vector<std::array<std::byte,20>> leaves;
  for(std::size_t i=0;i<54;++i) leaves.push_back(crypto::sha1(std::span(a).subspan(i*AICH_BLOCK_SIZE, AICH_BLOCK_SIZE)));
  auto level = leaves;
  while(level.size()>1){
    std::vector<std::array<std::byte,20>> nxt;
    for(std::size_t i=0;i<level.size();i+=2){
      if(i+1<level.size()){ std::array<std::byte,40> bb; for(int k=0;k<20;++k){bb[k]=level[i][k];bb[20+k]=level[i+1][k];} nxt.push_back(crypto::sha1(bb)); }
      else nxt.push_back(level[i]);
    }
    level.swap(nxt);
  }
  EXPECT_NE(aich_hash_bytes(a).bytes(), level[0]);
}
