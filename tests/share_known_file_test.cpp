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
