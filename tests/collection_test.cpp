#include <array>

#include <gtest/gtest.h>

#include "ed2k/infra/collection.hpp"

using namespace ed2k;
using namespace ed2k::infra;

namespace {
Ed2kFileLink file_link(std::string name, std::uint64_t size, std::string_view hash) {
  Ed2kFileLink link;
  link.name = std::move(name);
  link.size = size;
  link.hash = *FileHash::from_hex(hash);
  return link;
}
} // namespace

TEST(Collection, TextRoundTripUsesEd2kFileLinks) {
  Collection collection;
  collection.files.push_back(file_link("one.bin", 123, "00112233445566778899aabbccddeeff"));
  collection.files.push_back(file_link("two.bin", 456, "11223344556677889900aabbccddeeff"));

  auto text = write_collection_text(collection);
  auto parsed = parse_collection_text(text);

  ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
  ASSERT_EQ(parsed->files.size(), 2u);
  EXPECT_EQ(parsed->files[0].name, "one.bin");
  EXPECT_EQ(parsed->files[1].hash, collection.files[1].hash);
}

TEST(Collection, BinaryRoundTripPreservesFileLinks) {
  Collection collection;
  collection.files.push_back(file_link("one.bin", 123, "00112233445566778899aabbccddeeff"));
  collection.files.push_back(file_link("two.bin", 456, "11223344556677889900aabbccddeeff"));

  auto bytes = write_collection_binary(collection);
  auto parsed = parse_collection_binary(bytes);

  ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
  ASSERT_EQ(parsed->files.size(), 2u);
  EXPECT_EQ(parsed->files[0].name, collection.files[0].name);
  EXPECT_EQ(parsed->files[0].size, collection.files[0].size);
  EXPECT_EQ(parsed->files[0].hash, collection.files[0].hash);
  EXPECT_EQ(parsed->files[1].name, collection.files[1].name);
}
