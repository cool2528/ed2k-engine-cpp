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
// audit C1: MD4 校验失败必须重置该 part 的记账状态 (block_done 全 false + part_filled=0),
// 否则 :164 的幂等短路会让重下同一批块被静默丢弃 —— 损坏字节永久留盘, 该 part 永不可验。
// 场景: 先写满一个 part 的全部块 (内容与期望 hash 不符) -> 触发 MD4 校验并失败 -> 断言该 part
// 所有块被重新标记为未完成 -> 再用正确数据重写同一批块 -> 应能重新触发 MD4 并通过、整体 complete。
TEST(PartFile, MD4MismatchResetsPartStateForRedownload){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_md4_reset"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto correct = make_part_data(0x11, PART);
  auto corrupt = make_part_data(0xFF, PART);   // 内容不同 -> 组装后 MD4 与期望值不符
  auto h0 = md4_of(correct);                    // part 的真实期望 hash (仅 correct 数据能通过)
  {
  PartFile pf(path, PART, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {h0});
  std::size_t nb = static_cast<std::size_t>((PART + AICH_BLK - 1) / AICH_BLK);
  // 1) 写入损坏数据的全部块: 末块写入时 part 攒满触发 MD4 校验, 应失败 (block_corrupt)。
  for(std::size_t b=0; b<nb; ++b){
    std::uint64_t s = b*AICH_BLK, e = std::min(s+AICH_BLK, PART);
    auto w = pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                   std::span(corrupt).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
    if(b+1 == nb) EXPECT_FALSE(w.has_value()) << "末块写入应触发 MD4 校验并因内容损坏而失败";
  }
  EXPECT_FALSE(pf.complete());
  // 2) 状态应被重置: 该 part 的所有块应重新变为未完成 (block_done 全 false)。
  for(std::size_t b=0; b<nb; ++b)
    EXPECT_FALSE(pf.is_block_done(0, b)) << "block " << b << " 应在 MD4 失败后被重置为未完成";
  auto pend = pf.pending_blocks();
  EXPECT_EQ(pend.size(), nb) << "MD4 失败后该 part 全部块应重新变为待下载";
  // 3) 重下正确数据: 若 part_filled 未归零 (bug), 重写会导致累计字节数永远无法再等于整 part 长度,
  //    MD4 校验将不会再触发, complete() 会永久为 false —— 这正是本用例要捕获的回归。
  for(std::size_t b=0; b<nb; ++b){
    std::uint64_t s = b*AICH_BLK, e = std::min(s+AICH_BLK, PART);
    auto w = pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                   std::span(correct).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
    EXPECT_TRUE(w.has_value()) << "block " << b << " 重下正确数据应成功写入";
  }
  EXPECT_TRUE(pf.complete()) << "重下正确数据后该 part 应重新通过 MD4 校验并整体完成";
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
      std::uint32_t end = std::uint32_t(std::min<std::uint64_t>(off+blk, PART));
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

// === E1: 块级 .part.met 续传 ===
// 审计 E1: save_met() 此前只落盘整 part 粒度的 gaps(), 未完成 part 内已写入的块级进度不落盘。
// 暂停/取消丢失协程后, resume 只能靠 gaps() 判断"part 未完成"→ 该 part 全部块(含已下载的)重下,
// 对大文件多源下载浪费严重。本测试验证: 显式 save_met() 落盘未完成 part 的块位图, 重新打开后
// 已写入块被正确恢复为 done(不重下), 仅剩余块 pending; 补齐剩余块后 part 仍能正常触发 MD4 完成。
// 写入模式故意不连续(0..24 常规块 + 末块 52 短块 143360B), 同时覆盖"非前缀恢复模式"与"末块
// 长度不同于常规块"两个 part_filled 记账边界。
TEST(PartFile, ResumePersistsPartialBlockProgress){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_partial_persist"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART);
  auto h0 = md4_of(d0);
  auto fh = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  std::size_t nb = static_cast<std::size_t>((PART + AICH_BLK - 1) / AICH_BLK);
  ASSERT_EQ(nb, 53u);
  std::vector<std::size_t> written_blocks;
  for(std::size_t b=0;b<=24;++b) written_blocks.push_back(b);
  written_blocks.push_back(52);   // 末块(143360B, 短于常规 AICH_BLK), 与前缀不连续
  {
    PartFile pf(path, PART, fh, {h0});
    for(std::size_t b : written_blocks){
      std::uint64_t s = b*AICH_BLK, e = std::min(s+AICH_BLK, PART);
      auto w = pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                     std::span(d0).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
      EXPECT_TRUE(w.has_value()) << "block " << b;
    }
    EXPECT_FALSE(pf.complete());   // part 未整体完成(缺 25..51)
    for(std::size_t b : written_blocks) EXPECT_TRUE(pf.is_block_done(0,b)) << "block " << b;
    for(std::size_t b=25;b<=51;++b) EXPECT_FALSE(pf.is_block_done(0,b)) << "block " << b;
    pf.save_met();   // 显式 flush(暂停/取消路径的落盘时机), 落盘块级位图(E1)
  }
  // 重新打开(模拟 resume): 已写块应恢复为 done(不重下); 仅 25..51 pending。
  {
    PartFile pf(path, PART, fh, {h0});
    EXPECT_FALSE(pf.complete());
    for(std::size_t b : written_blocks)
      EXPECT_TRUE(pf.is_block_done(0,b)) << "resume 后 block " << b << " 应恢复为 done(此前已落盘)";
    for(std::size_t b=25;b<=51;++b)
      EXPECT_FALSE(pf.is_block_done(0,b)) << "block " << b << " 未写入, 应仍为 pending";
    auto pend = pf.pending_blocks();
    EXPECT_EQ(pend.size(), 27u) << "resume 后仅剩余 25..51 共 27 块应 pending(不应整 part 重下 53 块)";
    for(auto [p,b] : pend){ EXPECT_EQ(p, 0u); EXPECT_GE(b, 25u); EXPECT_LE(b, 51u); }
    // 补齐剩余块: part 应能正常触发 MD4 并完成(证 part_filled 记账在恢复后仍正确累计)。
    for(std::size_t b=25;b<=51;++b){
      std::uint64_t s = b*AICH_BLK, e = std::min(s+AICH_BLK, PART);
      auto w = pf.write_block(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e),
                     std::span(d0).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)));
      EXPECT_TRUE(w.has_value()) << "block " << b;
    }
    EXPECT_TRUE(pf.complete()) << "补齐剩余块后 part 应通过 MD4 校验并完成";
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
