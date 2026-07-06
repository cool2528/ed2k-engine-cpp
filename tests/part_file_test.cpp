#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include "ed2k/download/part_file.hpp"
#include "ed2k/metfile/known_part_met.hpp"
#include "crypto/md4.hpp"
using namespace ed2k; using namespace ed2k::download;
static constexpr std::uint64_t PART = 9728000;
static constexpr std::uint64_t AICH_BLK = AICH_BLOCK_SIZE;   // = ed2k::AICH_BLOCK_SIZE (aich_hasher.hpp)
static std::vector<std::byte> make_part_data(std::uint8_t fill, std::uint64_t len){
  return std::vector<std::byte>(len, std::byte(fill));
}
static PartHash md4_of(std::span<const std::byte> d){
  crypto::MD4 m; m.update(d); return PartHash::from_bytes(m.finish());
}
// 把 [0,size) 的所有 per-part 块依次写入 PartFile(块绝不跨 part 边界)
static void write_all_per_part(PartFile& pf, std::span<const std::byte> full, std::uint64_t size){
  std::size_t np = static_cast<std::size_t>((size + PART - 1) / PART);
  for(std::size_t p=0; p<np; ++p){
    std::uint64_t pstart = p*PART;
    std::uint64_t plen = std::min(PART, size - pstart);
    std::size_t nb = static_cast<std::size_t>((plen + AICH_BLK - 1) / AICH_BLK);
    for(std::size_t b=0; b<nb; ++b){
      std::uint64_t s = pstart + b*AICH_BLK;
      std::uint64_t e = std::min(s + AICH_BLK, pstart + plen);
      (void)pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                     full.subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
    }
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
  write_all_per_part(pf, full, size);
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
  write_all_per_part(pf, d0, PART);
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
    write_all_per_part(pf, full, PART*2); }
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
  // 只写覆盖 part0 的 per-part 块 0..52 (块 52 = [9584640, 9728000), 不跨界)
  std::size_t nb = static_cast<std::size_t>((PART + AICH_BLK - 1) / AICH_BLK);
  for(std::size_t b=0; b<nb; ++b){
    std::uint64_t s = b*AICH_BLK;
    std::uint64_t e = std::min(s + AICH_BLK, PART);
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
    EXPECT_TRUE(pf.complete());   // 所有 per-part 块写齐 -> part MD4 校验通过
  }
  std::filesystem::remove_all(dir);
}
TEST(PartFile, PendingBlocksAfterReopen){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_reopen"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART), d1 = make_part_data(0x22, PART);
  std::vector<std::byte> full; full.insert(full.end(), d0.begin(), d0.end()); full.insert(full.end(), d1.begin(), d1.end());
  // 完整下载 part0(per-part 块 0..52, 块 52 = [9584640, 9728000) 不跨界)
  { PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
    std::size_t nb = static_cast<std::size_t>((PART + AICH_BLK - 1) / AICH_BLK);
    for(std::size_t b=0; b<nb; ++b){
      std::uint64_t s = b*AICH_BLK;
      std::uint64_t e = std::min(s + AICH_BLK, PART);
      (void)pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                     std::span(full).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
    } }
  // 重新打开:part0 已验证 -> part0 所有块 done; part1 53 块 pending。
  {
  PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
  EXPECT_TRUE(pf.is_block_done(0, 0));
  EXPECT_FALSE(pf.is_block_done(1, 0));   // part1 未校验
  auto pend = pf.pending_blocks();
  EXPECT_EQ(pend.size(), 53u);
  for(auto [p,b] : pend) EXPECT_EQ(p, 1u);   // 全是 part1 的块
  }
  std::filesystem::remove_all(dir);
}
// per-part 块边界手验: part0 末块(52)= [9584640, 9728000) 恰止于 part0 终点;
// part1 首块(0)= [9728000, ...) 自 part 边界起。写入连续触发 part0 MD4; 重写幂等。
TEST(PartFile, PartBoundaryBlock){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_span"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  std::uint64_t size = PART*2;
  auto d0 = make_part_data(0x11, PART), d1 = make_part_data(0x22, PART);
  std::vector<std::byte> full; full.insert(full.end(), d0.begin(), d0.end()); full.insert(full.end(), d1.begin(), d1.end());
  {
    PartFile pf(path, size, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
    // 写 part0 块 0..51: part_filled_[0]=9584640, part0 未满。
    for(std::size_t b=0; b<=51; ++b){
      std::uint64_t s=b*AICH_BLK, e=s+AICH_BLK;
      EXPECT_TRUE(pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                                 std::span(full).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s))).has_value());
    }
    EXPECT_FALSE(pf.complete());   // part0 缺 143360B, part1 空
    // 写 part0 末块 52 = [9584640, 9728000): 完成 part0(MD4 触发)。
    std::uint64_t s52=52*AICH_BLK, e52=std::min(s52+AICH_BLK, PART);   // [9584640, 9728000)
    EXPECT_EQ(s52, 9584640u);
    EXPECT_EQ(e52, 9728000u);
    EXPECT_TRUE(pf.write_block(static_cast<std::uint32_t>(s52), static_cast<std::uint32_t>(e52),
                               std::span(full).subspan(static_cast<std::size_t>(s52), static_cast<std::size_t>(e52-s52))).has_value());
    EXPECT_FALSE(pf.complete());   // part0 done, part1 仍缺
    auto gaps = pf.gaps();
    ASSERT_EQ(gaps.size(), 1u);
    EXPECT_EQ(gaps[0].first, PART);   // 仅 part1 缺失
    // 幂等: 重写 part0 末块无副作用(不重复 MD4 / 不重复计数)
    EXPECT_TRUE(pf.write_block(static_cast<std::uint32_t>(s52), static_cast<std::uint32_t>(e52),
                               std::span(full).subspan(static_cast<std::size_t>(s52), static_cast<std::size_t>(e52-s52))).has_value());
    EXPECT_FALSE(pf.complete());
    // 补齐 part1: per-part 块 0..52
    std::size_t nb = static_cast<std::size_t>((PART + AICH_BLK - 1) / AICH_BLK);
    for(std::size_t b=0; b<nb; ++b){
      std::uint64_t s=PART + b*AICH_BLK, e=std::min(s+AICH_BLK, PART+PART);
      EXPECT_TRUE(pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                                 std::span(full).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s))).has_value());
    }
    EXPECT_TRUE(pf.complete());
  }
  std::filesystem::remove_all(dir);
}

// === P4c-3 M2: .part.met 续传 ===
// met-first 路径区分测试: 有效 met → 恢复 part_done_ 无需重哈希。三测试覆盖 met 与 rehash
// 分歧场景 (数据有效时两者一致, 故需构造分歧):
//   1) 有效 met + 盘上数据损坏 → met 受信 (rehash 会取消 done) → 证 met-first 生效
//   2) 损坏 met (bad magic) + 有效数据 → 回退 rehash → 恢复 done
//   3) 陈旧 met (part_hashes 不符) + 有效数据 → 忽略 met → rehash (rehash 与 met 分歧)

// (1) met 受信优先于盘上数据。设计权衡: met 仅在 part MD4 校验通过时写盘故受信,
//     牺牲盘上数据事后损坏的检测换 D1 性能 (避整文件重哈希)。
TEST(PartFile, ResumeFromPartMetTrustedOverCorruptData){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_met_trust"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART);
  auto h0 = md4_of(d0), h1 = md4_of(make_part_data(0x22, PART));
  auto fh = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  { PartFile pf(path, PART*2, fh, {h0,h1});                      // 写完 part0 → met 落盘 (part0 done, part1 gap)
    std::size_t nb = static_cast<std::size_t>((PART + AICH_BLK - 1) / AICH_BLK);
    for(std::size_t b=0;b<nb;++b){
      std::uint64_t s=b*AICH_BLK, e=std::min(s+AICH_BLK, PART);
      (void)pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                     std::span(d0).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
    }
    EXPECT_TRUE(pf.is_block_done(0,0));
    EXPECT_FALSE(pf.complete());
  }
  {
    auto met = path; met += ".part.met";
    std::ifstream m(met, std::ios::binary);
    ASSERT_TRUE(m.is_open());
    char first = 0;
    m.read(&first, 1);
    ASSERT_EQ(m.gcount(), 1);
    EXPECT_EQ(static_cast<unsigned char>(first), 0xE0u) << "PartFile should save aMule .part.met format";
  }
  { std::fstream z(path, std::ios::binary | std::ios::in | std::ios::out);  // 破坏 part0 数据 (大小不变 → 防截断不触发)
    std::vector<char> zero(static_cast<std::size_t>(PART), 0); z.seekp(0); z.write(zero.data(), static_cast<std::streamsize>(PART)); }
  { PartFile pf(path, PART*2, fh, {h0,h1});                      // 重开: met 标 part0 done → 受信 (rehash 读零→md4≠h0→取消)
    EXPECT_TRUE(pf.is_block_done(0,0)) << "met-first 应受信 part0 done (不重哈希)";
    EXPECT_FALSE(pf.is_block_done(1,0));
    auto pend = pf.pending_blocks();
    EXPECT_EQ(pend.size(), 53u);
    for(auto [p,b] : pend) EXPECT_EQ(p, 1u);
  }
  std::filesystem::remove_all(dir);
}
// (2) .part.met 损坏 (bad magic) → 回退 rehash_all (P4a 安全网)。数据有效 → rehash 恢复 part0 done。
TEST(PartFile, CorruptPartMetFallsBackToRehash){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_met_corrupt"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART);
  auto h0 = md4_of(d0), h1 = md4_of(make_part_data(0x22, PART));
  auto fh = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  { PartFile pf(path, PART*2, fh, {h0,h1});
    std::size_t nb = static_cast<std::size_t>((PART + AICH_BLK - 1) / AICH_BLK);
    for(std::size_t b=0;b<nb;++b){
      std::uint64_t s=b*AICH_BLK, e=std::min(s+AICH_BLK, PART);
      (void)pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                     std::span(d0).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
    }
  }
  auto met = path; met += ".part.met";
  { std::ofstream m(met, std::ios::binary | std::ios::trunc); std::array<char,1> bad{'\x99'}; m.write(bad.data(), 1); }
  { PartFile pf(path, PART*2, fh, {h0,h1});                      // met 解析失败 → rehash → part0 数据有效 → done
    EXPECT_TRUE(pf.is_block_done(0,0)) << "met 损坏 → rehash 回退 → part0 (数据有效) done";
    EXPECT_FALSE(pf.is_block_done(1,0));
  }
  std::filesystem::remove_all(dir);
}
// (3) 陈旧 .part.met (part_hashes 不匹配本文件) → 忽略 → rehash。分歧点: met gaps 空 → 误用会标 part0 done;
//     rehash 读 d0 → md4(d0)=h0≠h0_wrong → part0 not done。断言 not done → 证陈旧 met 被忽略 + rehash 执行。
TEST(PartFile, StalePartMetHashMismatchIgnored){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_met_stale"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART);
  auto h0 = md4_of(d0), h1 = md4_of(make_part_data(0x22, PART));
  auto h0_wrong = md4_of(make_part_data(0xFF, PART));            // 不同于 d0 的 part hash
  auto fh = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  { PartFile pf(path, PART*2, fh, {h0,h1});                      // 写完 part0 → met 落盘 (part_hashes=[h0,h1])
    std::size_t nb = static_cast<std::size_t>((PART + AICH_BLK - 1) / AICH_BLK);
    for(std::size_t b=0;b<nb;++b){
      std::uint64_t s=b*AICH_BLK, e=std::min(s+AICH_BLK, PART);
      (void)pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                     std::span(d0).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
    }
  }
  // 重开为 "不同文件": part0 hash 不符 → met 陈旧 → 忽略 → rehash。
  // rehash: part0 读 d0→md4=h0≠h0_wrong→not done; part1 无数据→not done。pending=106。
  { PartFile pf(path, PART*2, fh, {h0_wrong,h1});
    EXPECT_FALSE(pf.is_block_done(0,0)) << "陈旧 met 应忽略, rehash 读 d0≠h0_wrong → part0 not done";
    EXPECT_FALSE(pf.is_block_done(1,0));
    EXPECT_EQ(pf.pending_blocks().size(), 106u);
  }
  std::filesystem::remove_all(dir);
}

TEST(PartFile, AmulePartPathLoadsSiblingPartMet){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_amule_sibling_met"; std::filesystem::create_directories(dir);
  auto path = dir/"001.part";
  auto met = path; met += ".met";
  auto d0 = make_part_data(0x11, PART);
  auto h0 = md4_of(d0), h1 = md4_of(make_part_data(0x22, PART));
  auto fh = *FileHash::from_hex("00112233445566778899aabbccddeeff");

  {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    std::vector<char> zero(static_cast<std::size_t>(PART), 0);
    f.write(zero.data(), static_cast<std::streamsize>(zero.size()));
    f.seekp(static_cast<std::streamoff>(PART * 2 - 1));
    char last = 0;
    f.write(&last, 1);
  }
  {
    PartFileState st;
    st.hash = fh;
    st.part_hashes = {h0, h1};
    st.size = PART * 2;
    st.gaps = {{PART, PART * 2}};
    auto bytes = write_part_met(st);
    std::ofstream m(met, std::ios::binary | std::ios::trunc);
    m.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }

  {
    PartFile pf(path, PART * 2, fh, {h0, h1});
    EXPECT_TRUE(pf.is_block_done(0, 0)) << "aMule 001.part should load sibling 001.part.met";
    EXPECT_FALSE(pf.is_block_done(1, 0));
    auto pending = pf.pending_blocks();
    EXPECT_EQ(pending.size(), 53u);
    for(auto [p,b] : pending) EXPECT_EQ(p, 1u);
  }
  std::filesystem::remove_all(dir);
}
