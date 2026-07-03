#include <gtest/gtest.h>
#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/core/hash.hpp"
#include "crypto/md4.hpp"
using namespace ed2k; using namespace ed2k::download;
using namespace std::literals;

static constexpr std::uint64_t PART = PART_SIZE;
static constexpr std::uint64_t AICH_BLOCK = AICH_BLOCK_SIZE;

// 2-part 文件 per-part 块数 = 53(part0) + 53(part1) = 106 (满 part 各 53 块, 末块 143360B)。
static constexpr std::size_t BLOCKS_PER_PART = static_cast<std::size_t>((PART + AICH_BLOCK - 1) / AICH_BLOCK);
static constexpr std::size_t PERPART_2PART = BLOCKS_PER_PART * 2;

TEST(BlockAllocator, EmptyTwoPartAllMissing){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  ph.push_back(*PartHash::from_hex("112233445566778899aabbccddeeff00"));
  BlockAllocator a{PART*2, ph, std::nullopt};
  EXPECT_EQ(a.missing_count(), PERPART_2PART);   // 106 per-part 块
  auto next = a.next_block();
  ASSERT_TRUE(next.has_value());
  auto [part, bip, start, end] = *next;
  EXPECT_EQ(part, 0u); EXPECT_EQ(bip, 0u);
  EXPECT_EQ(start, 0u); EXPECT_EQ(end, AICH_BLOCK);
  a.mark_block_done(part, bip);
  EXPECT_EQ(a.missing_count(), PERPART_2PART - 1);
  EXPECT_FALSE(a.complete());
}

TEST(BlockAllocator, AllDoneReturnsComplete){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  BlockAllocator a{AICH_BLOCK, ph, std::nullopt}; // one part, one block
  auto next = a.next_block();
  ASSERT_TRUE(next.has_value());
  auto [part, bip, start, end] = *next;
  a.mark_block_done(part, bip);
  EXPECT_TRUE(a.complete());
  EXPECT_EQ(a.missing_count(), 0u);
  EXPECT_FALSE(a.next_block().has_value());
}

TEST(BlockAllocator, LastPartShortBlock){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  BlockAllocator a{100000, ph, std::nullopt}; // ~ half AICH block, 1 part 1 block
  auto next = a.next_block();
  ASSERT_TRUE(next.has_value());
  auto [part, bip, start, end] = *next;
  EXPECT_EQ(start, 0u); EXPECT_EQ(end, 100000u);   // size-capped
}

TEST(BlockAllocator, PartBlockEndsAtBoundary){
  // per-part 块绝不跨 part: part0 末块(52)= [9584640, 9728000), end 被 part 边界截断。
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  ph.push_back(*PartHash::from_hex("112233445566778899aabbccddeeff00"));
  BlockAllocator a{PART*2, ph, std::nullopt};
  // 消费 part0 前 52 块
  for(std::size_t i=0; i<52; ++i){
    auto nb=a.next_block(); ASSERT_TRUE(nb.has_value()); a.mark_block_done(std::get<0>(*nb), std::get<1>(*nb));
  }
  auto nb = a.next_block();
  ASSERT_TRUE(nb.has_value());
  auto [part, bip, start, end] = *nb;
  EXPECT_EQ(part, 0u); EXPECT_EQ(bip, 52u);
  EXPECT_EQ(start, 9584640u);
  EXPECT_EQ(end, 9728000u);   // part 边界截断 (非 9768960)
  // 下一块是 part1 块 0
  auto nb2 = a.next_block();
  ASSERT_TRUE(nb2.has_value());
  auto [p2, b2, s2, e2] = *nb2;
  EXPECT_EQ(p2, 1u); EXPECT_EQ(b2, 0u);
  EXPECT_EQ(s2, 9728000u);
}

TEST(BlockAllocator, RecoversFromPartFile){
  // PartFile 已完成 part0 -> part0 53 块 done; part1 53 块 pending。
  auto dir = std::filesystem::temp_directory_path()/"ed2k_ba_rec"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  std::vector<std::byte> d0(PART, std::byte(0x11)), d1(PART, std::byte(0x22));
  std::vector<std::byte> full; full.insert(full.end(), d0.begin(), d0.end()); full.insert(full.end(), d1.begin(), d1.end());
  crypto::MD4 m; m.update(d0); auto h0 = PartHash::from_bytes(m.finish());
  m = {}; m.update(d1); auto h1 = PartHash::from_bytes(m.finish());
  {
    PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {h0, h1});
    // 写覆盖 part0 的 per-part 块 0..52 (块 52 = [9584640, 9728000), 不跨界)
    std::size_t nb = static_cast<std::size_t>((PART + AICH_BLOCK - 1) / AICH_BLOCK);
    for(std::size_t b=0; b<nb; ++b){
      std::uint64_t s = b*AICH_BLOCK_SIZE;
      std::uint64_t e = std::min(s + AICH_BLOCK_SIZE, PART);
      (void)pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                     std::span(full).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
    }
  }
  {   // pf 析构关闭 fstream 后再 remove_all (Windows 文件句柄)
  PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {h0, h1});
  BlockAllocator a{PART*2, {h0, h1}, std::nullopt, pf};
  // part0 done -> part0 53 块 done; part1 53 块 missing
  EXPECT_EQ(a.missing_count(), 53u);
  auto nb = a.next_block();
  ASSERT_TRUE(nb.has_value());
  auto [part, bip, start, end] = *nb;
  EXPECT_EQ(part, 1u); EXPECT_EQ(bip, 0u);   // part1 块 0 优先(队首)
  EXPECT_EQ(start, 9728000u);
  EXPECT_EQ(end, 9728000u + AICH_BLOCK_SIZE);
  }
  std::filesystem::remove_all(dir);
}

TEST(BlockAllocator, RequeueBlock){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  BlockAllocator a{PART, ph, std::nullopt};   // 1 part, 53 块
  auto nb = a.next_block();
  ASSERT_TRUE(nb.has_value());
  auto [part, bip, start, end] = *nb;
  EXPECT_EQ(part, 0u); EXPECT_EQ(bip, 0u);
  a.requeue_block(part, bip);   // 块 (0,0) 重入队尾
  EXPECT_EQ(a.missing_count(), 53u);   // 仍未完成
  // 消费到队尾应再遇到块 (0,0)
  std::size_t seen=0;
  while(auto b = a.next_block()){
    if(std::get<0>(*b)==part && std::get<1>(*b)==bip) ++seen;
  }
  EXPECT_GE(seen, 1u);
}
