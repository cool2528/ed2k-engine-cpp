#include <gtest/gtest.h>
#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/core/hash.hpp"
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
