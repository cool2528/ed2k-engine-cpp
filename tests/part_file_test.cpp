#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include "ed2k/download/part_file.hpp"
#include "crypto/md4.hpp"
using namespace ed2k; using namespace ed2k::download;
static constexpr std::uint64_t PART = 9728000;
static std::vector<std::byte> make_part_data(std::uint8_t fill, std::uint64_t len){
  return std::vector<std::byte>(len, std::byte(fill));
}
static PartHash md4_of(std::span<const std::byte> d){
  crypto::MD4 m; m.update(d); return PartHash::from_bytes(m.finish());
}
// 把 [0,size) 的所有 flat 块依次写入 PartFile(块可跨 part 边界)
static void write_all_flat(PartFile& pf, std::span<const std::byte> full, std::uint64_t size){
  std::size_t nb = static_cast<std::size_t>((size + AICH_BLK - 1) / AICH_BLK);
  for(std::size_t g=0; g<nb; ++g){
    std::uint64_t s = g*AICH_BLK;
    std::uint64_t e = std::min(s + AICH_BLK, size);
    (void)pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                   full.subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
  }
}
TEST(PartFile, WritePartVerifiesAndCompletes){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_p4a_test1"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  std::uint64_t size = PART*2;
  auto d0 = make_part_data(0x11, PART), d1 = make_part_data(0x22, PART);
  std::vector<std::byte> full; full.insert(full.end(), d0.begin(), d0.end()); full.insert(full.end(), d1.begin(), d1.end());
  {
  PartFile pf(path, size, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
  EXPECT_FALSE(pf.complete());
  write_all_flat(pf, full, size);
  EXPECT_TRUE(pf.complete());
  }
  std::filesystem::remove_all(dir);
}
TEST(PartFile, WrongPartDataFails){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_p4a_test2"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART);
  auto wrong = md4_of(make_part_data(0xFF, PART));   // 错误 hash
  {
  PartFile pf(path, PART, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {wrong});
  write_all_flat(pf, d0, PART);
  EXPECT_FALSE(pf.complete());   // part MD4 校验失败 -> block_corrupt, part 未置 done
  }
  std::filesystem::remove_all(dir);
}
TEST(PartFile, ResumeSkipsVerifiedPart){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_p4a_test3"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART), d1 = make_part_data(0x22, PART);
  std::vector<std::byte> full; full.insert(full.end(), d0.begin(), d0.end()); full.insert(full.end(), d1.begin(), d1.end());
  // 先下载完整
  { PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
    write_all_flat(pf, full, PART*2); }
  // 重新打开:已校验的 part 应标记 done
  {
  PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
  EXPECT_TRUE(pf.complete());                          // 两 part 已校验
  auto missing = pf.missing_parts_peer_has({true,true});
  EXPECT_TRUE(missing.empty());
  }
  std::filesystem::remove_all(dir);
}
TEST(PartFile, GapsForMissing){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_p4a_test4"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART), d1 = make_part_data(0x22, PART);
  std::vector<std::byte> full; full.insert(full.end(), d0.begin(), d0.end()); full.insert(full.end(), d1.begin(), d1.end());
  {
  PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(make_part_data(0x22,PART))});
  // 只写覆盖 part0 的 flat 块(0..52, 块 52 跨界完成 part0)
  std::size_t nb = static_cast<std::size_t>((PART*2 + AICH_BLK - 1) / AICH_BLK);
  for(std::size_t g=0; g<nb; ++g){
    std::uint64_t s = g*AICH_BLK;
    if(s >= PART) break;   // 只到 part0 覆盖范围
    std::uint64_t e = std::min(s + AICH_BLK, PART*2);
    (void)pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                   std::span(full).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
  }
  EXPECT_TRUE(pf.complete() == false);
  auto g = pf.gaps();
  ASSERT_EQ(g.size(), 1u);
  EXPECT_EQ(g[0].first, PART);
  }
  std::filesystem::remove_all(dir);
}
TEST(PartFile, WriteBlockIdempotent){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_idem"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART);
  {
    PartFile pf(path, PART, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0)});
    // 写第 0 块两次:幂等,不重复计数
    std::size_t blk = 184320;
    auto b0 = make_part_data(0x11, blk);
    EXPECT_TRUE(pf.write_block(0, std::uint32_t(blk), b0).has_value());
    EXPECT_TRUE(pf.write_block(0, std::uint32_t(blk), b0).has_value());   // 重复写同块
    EXPECT_FALSE(pf.complete());   // 仅 1/53 块
  }
  std::filesystem::remove_all(dir);
}
TEST(PartFile, IncrementalBlocksCompletePart){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_incr"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART);
  {
    PartFile pf(path, PART, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0)});
    std::size_t blk = 184320;
    for(std::size_t off=0; off<PART; off+=blk){
      std::uint32_t start = std::uint32_t(off);
      std::uint32_t end = std::uint32_t(std::min(off+blk, PART));
      EXPECT_TRUE(pf.write_block(start, end, std::span(d0).subspan(off, end-start)).has_value());
    }
    EXPECT_TRUE(pf.complete());   // 所有 flat 块写齐 -> part MD4 校验通过
  }
  std::filesystem::remove_all(dir);
}
TEST(PartFile, PendingBlocksAfterReopen){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_reopen"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART), d1 = make_part_data(0x22, PART);
  std::vector<std::byte> full; full.insert(full.end(), d0.begin(), d0.end()); full.insert(full.end(), d1.begin(), d1.end());
  // 完整下载 part0(写覆盖 part0 的 flat 块 0..52, 块 52 跨界)
  { PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
    for(std::size_t g=0; ; ++g){
      std::uint64_t s = g*AICH_BLK;
      if(s >= PART) break;
      std::uint64_t e = std::min(s + AICH_BLK, PART*2);
      (void)pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                     std::span(full).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
    } }
  // 重新打开:part0 已验证。跨界块 52(横跨 part0/part1)因 part1 未验证而不 done。
  // pending = 块 52 + 块 53..105 = 54 个 flat 块。
  {
  PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
  EXPECT_TRUE(pf.is_block_done(0));
  EXPECT_FALSE(pf.is_block_done(52));   // 跨界块, part1 未校验
  auto pend = pf.pending_blocks();
  EXPECT_EQ(pend.size(), 54u);
  for(auto glb : pend) EXPECT_GE(glb, 52u);
  }
  std::filesystem::remove_all(dir);
}
// 跨界块手验: flat 块 52 = [9584640, 9768960) 横跨 part0(结束于 9728000)/part1 边界。
// 写入后应连续写盘, 给 part0 补 143360B(满 -> MD4 校验), 给 part1 补 40960B; 重写幂等。
TEST(PartFile, CrossBoundaryBlockSpansParts){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_span"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  std::uint64_t size = PART*2;
  auto d0 = make_part_data(0x11, PART), d1 = make_part_data(0x22, PART);
  std::vector<std::byte> full; full.insert(full.end(), d0.begin(), d0.end()); full.insert(full.end(), d1.begin(), d1.end());
  {
    PartFile pf(path, size, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
    // 写块 0..51(完全落在 part0 内): part_filled_[0]=9584640, part0 未满。
    for(std::size_t g=0; g<=51; ++g){
      std::uint64_t s=g*AICH_BLK, e=s+AICH_BLK;
      EXPECT_TRUE(pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                                 std::span(full).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s))).has_value());
    }
    EXPECT_FALSE(pf.complete());   // part0 缺 143360B, part1 空
    // 写跨界块 52: 完成 part0(MD4 触发), part1 得 40960B。
    std::uint64_t s52=52*AICH_BLK, e52=s52+AICH_BLK;   // [9584640, 9768960)
    EXPECT_EQ(s52, 9584640u);
    EXPECT_EQ(e52, 9768960u);
    EXPECT_TRUE(pf.write_block(static_cast<std::uint32_t>(s52), static_cast<std::uint32_t>(e52),
                               std::span(full).subspan(static_cast<std::size_t>(s52), static_cast<std::size_t>(e52-s52))).has_value());
    EXPECT_FALSE(pf.complete());   // part0 done, part1 仍缺
    auto gaps = pf.gaps();
    ASSERT_EQ(gaps.size(), 1u);
    EXPECT_EQ(gaps[0].first, PART);   // 仅 part1 缺失
    // 幂等: 重写块 52 无副作用(不重复 MD4 / 不重复计数)
    EXPECT_TRUE(pf.write_block(static_cast<std::uint32_t>(s52), static_cast<std::uint32_t>(e52),
                               std::span(full).subspan(static_cast<std::size_t>(s52), static_cast<std::size_t>(e52-s52))).has_value());
    EXPECT_FALSE(pf.complete());
    // 补齐 part1: 块 53..105
    std::size_t nb = static_cast<std::size_t>((size + AICH_BLK - 1) / AICH_BLK);
    for(std::size_t g=53; g<nb; ++g){
      std::uint64_t s=g*AICH_BLK, e=std::min(s+AICH_BLK, size);
      EXPECT_TRUE(pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                                 std::span(full).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s))).has_value());
    }
    EXPECT_TRUE(pf.complete());
  }
  std::filesystem::remove_all(dir);
}
