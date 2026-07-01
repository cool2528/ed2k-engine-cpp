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
TEST(Aich, FlatMerkleLoneChildMatchesManual){
  // 3 块:末位 lone。扁平后根应等于手算的 lone-child 归并。
  std::vector<std::byte> data(AICH_BLOCK_SIZE*3, std::byte(0x77));
  auto h0 = crypto::sha1(std::span(data).subspan(0, AICH_BLOCK_SIZE));
  auto h1 = crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE, AICH_BLOCK_SIZE));
  auto h2 = crypto::sha1(std::span(data).subspan(AICH_BLOCK_SIZE*2, AICH_BLOCK_SIZE));
  // 手算扁平 lone-child: level0=[h0,h1,h2], level1=[SHA1(h0||h1), h2(lone上提)], root=SHA1(L||h2)
  std::array<std::byte,40> ab; for(int i=0;i<20;++i){ab[i]=h0[i];ab[20+i]=h1[i];}
  auto L = crypto::sha1(ab);
  std::array<std::byte,40> rb; for(int i=0;i<20;++i){rb[i]=L[i];rb[20+i]=h2[i];}
  auto expected = crypto::sha1(rb);
  EXPECT_EQ(aich_hash_bytes(data).bytes(), expected);
}
TEST(Aich, FlatMerkleTwoChunkMatchesManual){
  // 跨 chunk 边界(>9728000 字节):两级与扁平必然不同,验证扁平
  std::size_t n = AICH_BLOCK_SIZE*54; // 54 块, 跨 CHUNK_SIZE(=53块/part)
  std::vector<std::byte> data(n, std::byte(0x77));
  std::vector<std::array<std::byte,20>> leaves;
  for(std::size_t i=0;i<54;++i) leaves.push_back(crypto::sha1(std::span(data).subspan(i*AICH_BLOCK_SIZE, AICH_BLOCK_SIZE)));
  // lone-child 归并手算根
  auto level = leaves;
  while(level.size()>1){
    std::vector<std::array<std::byte,20>> nxt;
    for(std::size_t i=0;i<level.size();i+=2){
      if(i+1<level.size()){ std::array<std::byte,40> b; for(int k=0;k<20;++k){b[k]=level[i][k];b[20+k]=level[i+1][k];} nxt.push_back(crypto::sha1(b)); }
      else nxt.push_back(level[i]);
    }
    level.swap(nxt);
  }
  EXPECT_EQ(aich_hash_bytes(data).bytes(), level[0]);
}
