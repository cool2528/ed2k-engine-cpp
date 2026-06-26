#include <gtest/gtest.h>
#include <vector>
#include "ed2k/hash/ed2k_hasher.hpp"
using namespace ed2k;
static std::vector<std::byte> fill(std::size_t n, std::uint8_t v){
  return std::vector<std::byte>(n, std::byte{v});
}
TEST(Ed2kHasher, SingleChunkOf0x55_Blue){
  auto data=fill(CHUNK_SIZE,0x55);
  auto r=hash_bytes(data, HashVariant::Blue);
  EXPECT_EQ(r.file_hash.to_hex(), "4127a47867b6110f0f86f2d9845fb374");
}
TEST(Ed2kHasher, SingleChunkOf0x55_Red){
  auto data=fill(CHUNK_SIZE,0x55);
  auto r=hash_bytes(data, HashVariant::Red);
  EXPECT_EQ(r.file_hash.to_hex(), "49e80f377b7e4e706dbd3ecc89f39306");
}
TEST(Ed2kHasher, EmptyFileIsMd4OfEmpty){
  auto r=hash_bytes({}, HashVariant::Blue);
  EXPECT_EQ(r.file_hash.to_hex(), "31d6cfe0d16ae931b73c59d7e0c089c0");
  EXPECT_EQ(r.part_hashes.size(), 1u);
}
TEST(Ed2kHasher, SmallFileSingleChunkUsesDirectMd4){
  auto data=fill(100,0x41);
  auto r=hash_bytes(data, HashVariant::Blue);
  EXPECT_EQ(r.part_hashes.size(), 1u);
  EXPECT_EQ(r.file_hash, r.part_hashes[0]); // 单块直接用块哈希
}
TEST(Ed2kHasher, TwoChunksConcatHash){
  auto data=fill(CHUNK_SIZE+10,0x42);
  auto r=hash_bytes(data, HashVariant::Blue);
  EXPECT_EQ(r.part_hashes.size(), 2u);
  EXPECT_NE(r.file_hash, r.part_hashes[0]); // 多块为根哈希
}
