#include <gtest/gtest.h>
#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/core/hash.hpp"
#include "crypto/md4.hpp"
using namespace ed2k; using namespace ed2k::download;
using namespace std::literals;

static constexpr std::uint64_t PART = PART_SIZE;
static constexpr std::uint64_t AICH_BLOCK = AICH_BLOCK_SIZE;

TEST(BlockAllocator, EmptyTwoPartAllMissing){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  ph.push_back(*PartHash::from_hex("112233445566778899aabbccddeeff00"));
  BlockAllocator a{PART*2, ph, std::nullopt};
  EXPECT_EQ(a.missing_count(), 2*53); // 53 blocks per part (53*184320 = 9768960 which is slightly over 9728000, last partial)
  auto next = a.next_block();
  ASSERT_TRUE(next.has_value());
  auto [pi, ai, start, end] = *next;
  EXPECT_EQ(pi, 0u); EXPECT_EQ(ai, 0u); EXPECT_EQ(start, 0u); EXPECT_EQ(end, AICH_BLOCK);
  a.mark_block_done(pi, ai);
  EXPECT_EQ(a.missing_count(), 2*53 - 1);
  EXPECT_FALSE(a.complete());
}

TEST(BlockAllocator, AllDoneReturnsComplete){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  BlockAllocator a{AICH_BLOCK, ph, std::nullopt}; // one part, one block
  auto next = a.next_block();
  ASSERT_TRUE(next.has_value());
  auto [pi, ai, start, end] = *next;
  a.mark_block_done(pi, ai);
  EXPECT_TRUE(a.complete());
  EXPECT_EQ(a.missing_count(), 0u);
  EXPECT_FALSE(a.next_block().has_value());
}

TEST(BlockAllocator, LastPartShortBlock){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  BlockAllocator a{100000, ph, std::nullopt}; // ~ half AICH block
  auto next = a.next_block();
  ASSERT_TRUE(next.has_value());
  auto [pi, ai, start, end] = *next;
  EXPECT_EQ(start, 0u); EXPECT_EQ(end, 100000u);
}

TEST(BlockAllocator, RecoversFromPartFile){
  // PartFile 已完成 part0 -> BlockAllocator 应只 pending part1 的 53 块
  auto dir = std::filesystem::temp_directory_path()/"ed2k_ba_rec"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  std::vector<std::byte> d0(PART, std::byte(0x11)), d1(PART, std::byte(0x22));
  crypto::MD4 m; m.update(d0); auto h0 = PartHash::from_bytes(m.finish());
  m = {}; m.update(d1); auto h1 = PartHash::from_bytes(m.finish());
  {
    PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {h0, h1});
    pf.write_block(0, std::uint32_t(PART), d0);   // part0 done
  }
  {   // pf 析构关闭 fstream 后再 remove_all (Windows 文件句柄)
  PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {h0, h1});
  BlockAllocator a{PART*2, {h0, h1}, std::nullopt, pf};
  EXPECT_EQ(a.missing_count(), 53u);   // 仅 part1
  auto nb = a.next_block();
  ASSERT_TRUE(nb.has_value());
  auto [pi, ai, start, end] = *nb;
  EXPECT_EQ(pi, 1u); EXPECT_EQ(ai, 0u);
  }
  std::filesystem::remove_all(dir);
}

TEST(BlockAllocator, RequeueBlock){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  BlockAllocator a{PART, ph, std::nullopt};   // 53 块
  auto nb = a.next_block();
  ASSERT_TRUE(nb.has_value());
  auto [pi, ai, start, end] = *nb;
  EXPECT_EQ(ai, 0u);
  a.requeue_block(pi, ai);   // 块 0 重入队尾
  EXPECT_EQ(a.missing_count(), 53u);   // 仍未完成
  // 消费到队尾应再遇到块 0
  std::size_t seen=0;
  while(auto b = a.next_block()){ if(std::get<0>(*b)==pi && std::get<1>(*b)==ai) ++seen; if(a.missing_count()==0) break; }
  EXPECT_GE(seen, 1u);
}
