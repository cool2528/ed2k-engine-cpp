#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

#include "ed2k/codec/tag.hpp"
#include "ed2k/kad/indexed.hpp"

using namespace ed2k;
using namespace ed2k::kad;
using namespace std::chrono_literals;

namespace {
KadID kid(const char* hex) {
  return *KadID::from_hex(hex);
}

codec::Tag string_tag(std::uint8_t name_id, std::string value) {
  codec::Tag tag;
  tag.name_str = std::string(1, static_cast<char>(name_id));
  tag.value = std::move(value);
  return tag;
}

codec::Tag int_tag(std::uint8_t name_id, std::uint64_t value) {
  codec::Tag tag;
  tag.name_str = std::string(1, static_cast<char>(name_id));
  tag.value = value;
  return tag;
}

KadSearchEntry file_entry(const char* file_hex, std::string name, std::uint64_t size) {
  return KadSearchEntry{
      .answer_id = kid(file_hex),
      .tags = {string_tag(tag::filename, std::move(name)), int_tag(tag::file_size, size)},
  };
}

KadSearchEntry source_entry(const char* source_hex, std::uint16_t tcp_port, std::uint16_t udp_port,
                            std::uint64_t size) {
  return KadSearchEntry{
      .answer_id = kid(source_hex),
      .tags = {int_tag(tag::source_type, 1), int_tag(tag::source_port, tcp_port),
               int_tag(tag::source_udp_port, udp_port), int_tag(tag::file_size, size)},
  };
}

KadSearchEntry note_entry(const char* source_hex, std::string description, std::uint64_t size) {
  return KadSearchEntry{
      .answer_id = kid(source_hex),
      .tags = {string_tag(tag::description, std::move(description)), int_tag(tag::file_rating, 4),
               int_tag(tag::file_size, size)},
  };
}
} // namespace

TEST(KadIndexed, KeywordEntriesExpireByTtl) {
  KadIndexed indexed(1s);
  const auto now = KadIndexed::clock::time_point{1s};
  const auto key = kid("00112233445566778899aabbccddeeff");
  const auto file = file_entry("0102030405060708090a0b0c0d0e0f10", "ubuntu.iso", 123456789ull);

  indexed.add_keyword(key, file, now);

  auto fresh = indexed.search_keyword(key, 50, now + 500ms);
  ASSERT_EQ(fresh.size(), 1u);
  EXPECT_EQ(fresh[0].answer_id, file.answer_id);

  auto expired = indexed.search_keyword(key, 50, now + 1500ms);
  EXPECT_TRUE(expired.empty());
}

TEST(KadIndexed, SourceEntriesDeduplicateAndFilterBySize) {
  KadIndexed indexed(1h);
  const auto now = KadIndexed::clock::time_point{1s};
  const auto file = kid("00112233445566778899aabbccddeeff");
  auto first = source_entry("0102030405060708090a0b0c0d0e0f10", 4662, 4665, 123456789ull);
  auto updated = source_entry("0102030405060708090a0b0c0d0e0f10", 4663, 4666, 123456789ull);
  auto other_size = source_entry("101112131415161718191a1b1c1d1e1f", 5662, 5665, 42);

  indexed.add_source(file, first, now);
  indexed.add_source(file, updated, now + 100ms);
  indexed.add_source(file, other_size, now + 100ms);

  auto filtered = indexed.search_sources(file, 123456789ull, 50, now + 200ms);
  ASSERT_EQ(filtered.size(), 1u);
  EXPECT_EQ(filtered[0].answer_id, updated.answer_id);
  EXPECT_EQ(source_tcp_port(filtered[0]), 4663);
  EXPECT_EQ(source_udp_port(filtered[0]), 4666);

  auto any_size = indexed.search_sources(file, 0, 50, now + 200ms);
  EXPECT_EQ(any_size.size(), 2u);
}

TEST(KadIndexed, NotesExpireAndFilterBySize) {
  KadIndexed indexed(1s);
  const auto now = KadIndexed::clock::time_point{1s};
  const auto file = kid("00112233445566778899aabbccddeeff");
  const auto note = note_entry("0102030405060708090a0b0c0d0e0f10", "works", 123456789ull);
  const auto other_size = note_entry("101112131415161718191a1b1c1d1e1f", "wrong", 42);

  indexed.add_note(file, note, now);
  indexed.add_note(file, other_size, now);

  auto filtered = indexed.search_notes(file, 123456789ull, 50, now + 500ms);
  ASSERT_EQ(filtered.size(), 1u);
  EXPECT_EQ(filtered[0].answer_id, note.answer_id);

  auto expired = indexed.search_notes(file, 0, 50, now + 1500ms);
  EXPECT_TRUE(expired.empty());
}
