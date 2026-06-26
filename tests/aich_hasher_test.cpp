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
