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
TEST(PartFile, WritePartVerifiesAndCompletes){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_p4a_test1"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  std::uint64_t size = PART*2;
  auto d0 = make_part_data(0x11, PART), d1 = make_part_data(0x22, PART);
  {
  PartFile pf(path, size, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
  EXPECT_FALSE(pf.complete());
  EXPECT_TRUE(pf.write_block(0, PART, d0).has_value());
  EXPECT_FALSE(pf.complete());
  EXPECT_TRUE(pf.write_block(PART, 2*PART, d1).has_value());
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
  auto r = pf.write_block(0, PART, d0);
  EXPECT_FALSE(r.has_value());
  if(!r) EXPECT_EQ(r.error(), make_error_code(errc::block_corrupt));
  }
  std::filesystem::remove_all(dir);
}
TEST(PartFile, ResumeSkipsVerifiedPart){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_p4a_test3"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  auto d0 = make_part_data(0x11, PART), d1 = make_part_data(0x22, PART);
  // 先下载完整
  { PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(d1)});
    pf.write_block(0, PART, d0); pf.write_block(PART, 2*PART, d1); }
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
  auto d0 = make_part_data(0x11, PART);
  {
  PartFile pf(path, PART*2, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {md4_of(d0), md4_of(make_part_data(0x22,PART))});
  pf.write_block(0, PART, d0);                         // part0 done, part1 missing
  auto g = pf.gaps();
  ASSERT_EQ(g.size(), 1u);
  EXPECT_EQ(g[0].first, PART);
  }
  std::filesystem::remove_all(dir);
}
