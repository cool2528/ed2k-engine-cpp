#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include "ed2k/share/known_file.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
using namespace ed2k;

namespace {
std::filesystem::path temp_dir(const char* name) {
  auto p = std::filesystem::temp_directory_path() / name;
  std::filesystem::remove_all(p);
  std::filesystem::create_directories(p);
  return p;
}

void write_bytes(const std::filesystem::path& p, std::span<const std::byte> data) {
  std::ofstream f(p, std::ios::binary | std::ios::trunc);
  f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}
}

TEST(ShareKnownFile, KnownMetRoundTripPreservesCoreTags) {
  share::KnownFile f;
  f.hash = *FileHash::from_hex("4127a47867b6110f0f86f2d9845fb374");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.part_hashes = { *PartHash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0") };
  f.name = "shared.bin";
  f.path = "D:/share/shared.bin";
  f.size = 12345678901ull;

  auto bytes = share::write_known_files(std::array<share::KnownFile, 1>{f});
  auto out = share::parse_known_files(bytes);

  ASSERT_TRUE(out.has_value()) << out.error().message();
  ASSERT_EQ(out->size(), 1u);
  EXPECT_EQ((*out)[0].hash, f.hash);
  EXPECT_EQ((*out)[0].aich_root, f.aich_root);
  EXPECT_EQ((*out)[0].part_hashes, f.part_hashes);
  EXPECT_EQ((*out)[0].name, f.name);
  EXPECT_EQ((*out)[0].size, f.size);
}

TEST(ShareKnownFile, Known2MetRoundTripPreservesAichRootAndLeaves) {
  share::Known2Entry e;
  e.hash = *FileHash::from_hex("4127a47867b6110f0f86f2d9845fb374");
  e.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  e.part_leaves = {
    *AICHHash::from_base32("CLSTIB6UTXRQ2X6VPY3OSZCHB2SYDBY2"),
    *AICHHash::from_base32("S24JCXJTEJZH3L4OZGNJOO7VNI6S7EVJ")
  };

  auto bytes = share::write_known2_met(std::array<share::Known2Entry, 1>{e});
  auto out = share::parse_known2_met(bytes);

  ASSERT_TRUE(out.has_value()) << out.error().message();
  ASSERT_EQ(out->size(), 1u);
  EXPECT_EQ((*out)[0], e);
}

TEST(ShareKnownFile, ScanDirIndexesRegularFiles) {
  auto dir = temp_dir("ed2k_share_scan");
  auto file = dir / "payload.bin";
  std::vector<std::byte> data(4096);
  for(std::size_t i = 0; i < data.size(); ++i) data[i] = std::byte(i & 0xff);
  write_bytes(file, data);

  share::KnownFileDB db;
  auto r = db.scan_dir(dir);

  ASSERT_TRUE(r.has_value()) << r.error().message();
  ASSERT_EQ(db.files().size(), 1u);
  auto h = hash_bytes(data);
  auto aich = aich_hash_bytes(data);
  auto* known = db.find(h.file_hash);
  ASSERT_NE(known, nullptr);
  EXPECT_EQ(known->path, file);
  EXPECT_EQ(known->name, "payload.bin");
  EXPECT_EQ(known->size, data.size());
  EXPECT_EQ(known->hash, h.file_hash);
  EXPECT_EQ(known->part_hashes, h.part_hashes);
  EXPECT_EQ(known->aich_root, aich);
  std::filesystem::remove_all(dir);
}

// known_from_path 应把文件 mtime 写入 date 字段(known.met 复用键的一部分)
TEST(KnownFileDB, ScanFillsDateFromMtime) {
  auto dir = temp_dir("ed2k_share_scan_date");
  auto file = dir / "a.bin";
  std::vector<std::byte> data(1024, std::byte{'x'});
  write_bytes(file, data);

  share::KnownFileDB db;
  ASSERT_TRUE(db.scan_dir(dir).has_value());
  ASSERT_EQ(db.files().size(), 1u);
  EXPECT_NE(db.files()[0].date, 0u);
  std::filesystem::remove_all(dir);
}

// 缓存中 (name,size,date) 匹配时跳过重哈希: 内容被改但三元组不变 -> 沿用缓存 hash
TEST(KnownFileDB, ScanReusesCacheWhenTripleMatches) {
  auto dir = temp_dir("ed2k_share_scan_cache");
  auto file = dir / "a.bin";
  std::vector<std::byte> data_x(1024, std::byte{'x'});
  write_bytes(file, data_x);

  share::KnownFileDB first;
  ASSERT_TRUE(first.scan_dir(dir).has_value());
  const auto cached_hash = first.files()[0].hash;
  const auto cached_date = first.files()[0].date;
  const auto mtime = std::filesystem::last_write_time(file);

  std::vector<std::byte> data_y(1024, std::byte{'y'});   // 同尺寸不同内容
  write_bytes(file, data_y);
  std::filesystem::last_write_time(file, mtime);         // 恢复 mtime -> 三元组不变

  share::KnownFileDB second;
  ASSERT_TRUE(second.scan_dir(dir, &first).has_value());
  ASSERT_EQ(second.files().size(), 1u);
  // mtime 恢复后 date 字段应与缓存一致(文件系统精度加固: 直接比较扫描得到的 date, 而非
  // 假设 last_write_time 往返在所有文件系统上都精确到位)。
  ASSERT_EQ(second.files()[0].date, cached_date);
  EXPECT_EQ(second.files()[0].hash, cached_hash);         // 复用而非重哈希

  share::KnownFileDB third;
  ASSERT_TRUE(third.scan_dir(dir).has_value());           // 无缓存 -> 真重哈希
  EXPECT_NE(third.files()[0].hash, cached_hash);
  std::filesystem::remove_all(dir);
}

// 缓存条目 date==0(构造时代表 mtime 读取失败)不得与真实文件(date!=0)误判命中:
// 复现 fdate==0 探测被跳过场景的另一面——即便探测未被跳过, date 比较本身也应拒绝该匹配。
// (对 fdate==0 时探测被直接跳过的分支, 以代码内联的一行 guard + 审查覆盖, 详见 known_file.cpp)
TEST(KnownFileDB, ScanDoesNotReuseCacheEntryWithZeroDate) {
  auto dir = temp_dir("ed2k_share_scan_cache_zero_date");
  auto file = dir / "b.bin";
  std::vector<std::byte> data(1024, std::byte{'z'});
  write_bytes(file, data);

  share::KnownFileDB first;
  ASSERT_TRUE(first.scan_dir(dir).has_value());
  ASSERT_EQ(first.files().size(), 1u);
  const auto real_hash = first.files()[0].hash;
  const auto real_size = first.files()[0].size;

  // 手工构造一条 date==0 的伪缓存条目, 与真实文件同名同大小, 但哈希是假的(全零哈希)
  share::KnownFileDB fake_cache;
  share::KnownFile fake;
  fake.hash = FileHash{};
  fake.name = "b.bin";
  fake.size = real_size;
  fake.date = 0;
  fake_cache.add(std::move(fake));

  share::KnownFileDB second;
  ASSERT_TRUE(second.scan_dir(dir, &fake_cache).has_value());
  ASSERT_EQ(second.files().size(), 1u);
  // 真实文件 mtime 不为 0, 与缓存 date==0 不相等 -> 不应命中伪缓存, 必须落回真实哈希
  EXPECT_NE(second.files()[0].date, 0u);
  EXPECT_EQ(second.files()[0].hash, real_hash);
  std::filesystem::remove_all(dir);
}

// 请求计数: note_request 累加, 未知 hash 返回 0, adopt 迁移旧计数
TEST(KnownFileDB, RequestCounting) {
  share::KnownFileDB db;
  auto h = *FileHash::from_hex("4127a47867b6110f0f86f2d9845fb374");
  EXPECT_EQ(db.request_count(h), 0u);
  db.note_request(h);
  db.note_request(h);
  EXPECT_EQ(db.request_count(h), 2u);

  share::KnownFileDB rebuilt;
  rebuilt.adopt_request_counts(db);
  EXPECT_EQ(rebuilt.request_count(h), 2u);
}

TEST(ShareKnownFile, PartFileConvertsCompletedFileToKnownFile) {
  auto dir = temp_dir("ed2k_share_partfile");
  auto file = dir / "complete.bin";
  std::vector<std::byte> data(4096, std::byte{0x5a});
  auto h = hash_bytes(data);
  auto aich = aich_hash_bytes(data);

  {
    download::PartFile pf(file, data.size(), h.file_hash, h.part_hashes);
    auto w = pf.write_block(0, data.size(), data);
    ASSERT_TRUE(w.has_value()) << w.error().message();
    ASSERT_TRUE(pf.complete());

    auto known = pf.to_known_file();
    ASSERT_TRUE(known.has_value()) << known.error().message();
    EXPECT_EQ(known->path, file);
    EXPECT_EQ(known->name, "complete.bin");
    EXPECT_EQ(known->size, data.size());
    EXPECT_EQ(known->hash, h.file_hash);
    EXPECT_EQ(known->part_hashes, h.part_hashes);
    EXPECT_EQ(known->aich_root, aich);
  }
  std::filesystem::remove_all(dir);
}
