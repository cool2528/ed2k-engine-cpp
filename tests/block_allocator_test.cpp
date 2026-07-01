#include <gtest/gtest.h>
#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/core/hash.hpp"
#include "crypto/md4.hpp"
using namespace ed2k; using namespace ed2k::download;
using namespace std::literals;

static constexpr std::uint64_t PART = PART_SIZE;
static constexpr std::uint64_t AICH_BLOCK = AICH_BLOCK_SIZE;

// 2-part 文件 flat 块数 = ceil(2*PART / AICH_BLOCK) = ceil(105.55) = 106
static constexpr std::size_t FLAT_BLOCKS_2PART = static_cast<std::size_t>((PART*2 + AICH_BLOCK - 1) / AICH_BLOCK);

TEST(BlockAllocator, EmptyTwoPartAllMissing){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  ph.push_back(*PartHash::from_hex("112233445566778899aabbccddeeff00"));
  BlockAllocator a{PART*2, ph, std::nullopt};
  EXPECT_EQ(a.missing_count(), FLAT_BLOCKS_2PART);   // 106 flat 块
  auto next = a.next_block();
  ASSERT_TRUE(next.has_value());
  auto [global, start, end] = *next;
  EXPECT_EQ(global, 0u); EXPECT_EQ(start, 0u); EXPECT_EQ(end, AICH_BLOCK);
  a.mark_block_done(global);
  EXPECT_EQ(a.missing_count(), FLAT_BLOCKS_2PART - 1);
  EXPECT_FALSE(a.complete());
}

TEST(BlockAllocator, AllDoneReturnsComplete){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  BlockAllocator a{AICH_BLOCK, ph, std::nullopt}; // one part, one flat block
  auto next = a.next_block();
  ASSERT_TRUE(next.has_value());
  auto [global, start, end] = *next;
  a.mark_block_done(global);
  EXPECT_TRUE(a.complete());
  EXPECT_EQ(a.missing_count(), 0u);
  EXPECT_FALSE(a.next_block().has_value());
}

TEST(BlockAllocator, LastPartShortBlock){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  BlockAllocator a{100000, ph, std::nullopt}; // ~ half AICH block, 1 flat block
  auto next = a.next_block();
  ASSERT_TRUE(next.has_value());
  auto [global, start, end] = *next;
  EXPECT_EQ(start, 0u); EXPECT_EQ(end, 100000u);   // size-capped, NOT part-capped
}

TEST(BlockAllocator, FlatBlockSpansPartBoundary){
  // 块 52 = [9584640, 9768960) 横跨 part0/part1 边界(9728000): end 不被 part 截断。
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  ph.push_back(*PartHash::from_hex("112233445566778899aabbccddeeff00"));
  BlockAllocator a{PART*2, ph, std::nullopt};
  // 消费到块 52
  for(std::size_t i=0; i<52; ++i){ auto nb=a.next_block(); ASSERT_TRUE(nb.has_value()); a.mark_block_done(std::get<0>(*nb)); }
  auto nb = a.next_block();
  ASSERT_TRUE(nb.has_value());
  auto [global, start, end] = *nb;
  EXPECT_EQ(global, 52u);
  EXPECT_EQ(start, 9584640u);
  EXPECT_EQ(end, 9768960u);   // 跨界: 越过 part0 终点 9728000
}

TEST(BlockAllocator, RecoversFromPartFile){
  // PartFile 已完成 part0 -> 跨界块 52(part1 未校验) + part1 块 53..105 共 54 块 pending
  auto dir = std::filesystem::temp_directory_path()/"ed2k_ba_rec"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  std::vector<std::byte> d0(PART, std::byte(0x11)), d1(PART, std::byte(0x22));
  std::vector<std::byte> full; full.insert(full.end(), d0.begin(), d0.end()); full.insert(full.end(), d1.begin(), d1.end());
  crypto::MD4 m; m.update(d0); auto h0 = PartHash::from_bytes(m.finish());
  m = {}; m.update(d1); auto h1 = PartHash::from_bytes(m.finish());
  {
    PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {h0, h1});
    // 写覆盖 part0 的 flat 块 0..52(块 52 跨界完成 part0)
    for(std::size_t g=0; ; ++g){
      std::uint64_t s = g*AICH_BLOCK_SIZE;
      if(s >= PART) break;
      std::uint64_t e = std::min(s + AICH_BLOCK_SIZE, PART*2);
      (void)pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                     std::span(full).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
    }
  }
  {   // pf 析构关闭 fstream 后再 remove_all (Windows 文件句柄)
  PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {h0, h1});
  BlockAllocator a{PART*2, {h0, h1}, std::nullopt, pf};
  // part0 done -> 块 0..51 done; 跨界块 52 + 块 53..105 = 54 块 missing
  EXPECT_EQ(a.missing_count(), 54u);
  auto nb = a.next_block();
  ASSERT_TRUE(nb.has_value());
  auto [global, start, end] = *nb;
  EXPECT_EQ(global, 52u);   // 跨界块优先(队首)
  EXPECT_EQ(start, 9584640u);
  EXPECT_EQ(end, 9768960u);
  }
  std::filesystem::remove_all(dir);
}

TEST(BlockAllocator, RequeueBlock){
  std::vector<PartHash> ph;
  ph.push_back(*PartHash::from_hex("00112233445566778899aabbccddeeff"));
  BlockAllocator a{PART, ph, std::nullopt};   // 53 flat 块
  auto nb = a.next_block();
  ASSERT_TRUE(nb.has_value());
  auto [global, start, end] = *nb;
  EXPECT_EQ(global, 0u);
  a.requeue_block(global);   // 块 0 重入队尾
  EXPECT_EQ(a.missing_count(), 53u);   // 仍未完成
  // 消费到队尾应再遇到块 0
  std::size_t seen=0;
  while(auto b = a.next_block()){ if(std::get<0>(*b)==global) ++seen; if(a.missing_count()==0) break; }
  EXPECT_GE(seen, 1u);
}
