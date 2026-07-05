#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/codec/tag.hpp"
#include "ed2k/metfile/known_part_met.hpp"
using namespace ed2k;
namespace {
constexpr std::uint8_t PARTFILE_VERSION = 0xE0;
constexpr std::uint8_t PARTFILE_VERSION_LARGEFILE = 0xE2;
constexpr std::uint8_t FT_FILENAME = 0x01;
constexpr std::uint8_t FT_FILESIZE = 0x02;
constexpr std::uint8_t FT_GAPSTART = 0x09;
constexpr std::uint8_t FT_GAPEND = 0x0A;
constexpr std::uint8_t FT_INTERNAL_GAPS = 0xF0;
constexpr std::uint64_t PART = 9728000;

std::string gap_name(std::uint8_t prefix, std::uint32_t index) {
  std::string s(1, static_cast<char>(prefix));
  s += std::to_string(index);
  return s;
}

void write_id_int_tag(codec::ByteWriter& w, std::uint8_t name, std::uint64_t value, bool large) {
  w.u8((large ? codec::tagtype::Uint64 : codec::tagtype::Uint32) | codec::tagtype::NameFlag);
  w.u8(name);
  if(large) w.u64(value);
  else w.u32(static_cast<std::uint32_t>(value));
}

void write_id_string_tag(codec::ByteWriter& w, std::uint8_t name, std::string_view value) {
  w.u8(codec::tagtype::String | codec::tagtype::NameFlag);
  w.u8(name);
  w.string16(value);
}

void write_named_int_tag(codec::ByteWriter& w, std::string_view name, std::uint64_t value, bool large) {
  w.u8(large ? codec::tagtype::Uint64 : codec::tagtype::Uint32);
  w.string16(name);
  if(large) w.u64(value);
  else w.u32(static_cast<std::uint32_t>(value));
}

std::vector<std::byte> make_amule_part_met(
    std::uint8_t version,
    const FileHash& hash,
    std::span<const PartHash> part_hashes,
    std::uint64_t size,
    std::span<const std::pair<std::uint64_t, std::uint64_t>> gaps) {
  bool large = version == PARTFILE_VERSION_LARGEFILE;
  codec::ByteWriter w;
  w.u8(version);
  w.u32(0);
  w.hash16(hash);
  w.u16(static_cast<std::uint16_t>(part_hashes.size()));
  for(const auto& part_hash : part_hashes) w.hash16(part_hash);
  w.u32(static_cast<std::uint32_t>(2 + gaps.size() * 2));
  write_id_string_tag(w, FT_FILENAME, "sample.bin");
  write_id_int_tag(w, FT_FILESIZE, size, large);
  for(std::uint32_t i = 0; i < gaps.size(); ++i) {
    write_named_int_tag(w, gap_name(FT_GAPSTART, i), gaps[i].first, large);
    write_named_int_tag(w, gap_name(FT_GAPEND, i), gaps[i].second, large);
  }
  return w.take();
}

std::vector<std::byte> make_legacy_internal_part_met(const PartFileState& p) {
  codec::ByteWriter w;
  w.u8(0x0E);
  w.u32(0);
  w.hash16(p.hash);
  w.u16(static_cast<std::uint16_t>(p.part_hashes.size()));
  for(const auto& part_hash : p.part_hashes) w.hash16(part_hash);

  std::vector<std::byte> gapblob;
  {
    codec::ByteWriter gw;
    gw.u32(static_cast<std::uint32_t>(p.gaps.size()));
    for(const auto& [start, end] : p.gaps) {
      gw.u64(start);
      gw.u64(end);
    }
    gapblob = gw.take();
  }
  codec::Tag t;
  t.name_id = FT_INTERNAL_GAPS;
  t.value = gapblob;
  w.u32(1);
  codec::write_tag(w, t);
  return w.take();
}

struct RawTagHeader {
  std::uint8_t type = 0;
  std::uint8_t name_id = 0;
  std::string name_str;
};

std::vector<RawTagHeader> raw_part_met_tags(std::span<const std::byte> bytes) {
  codec::ByteReader r(bytes);
  (void)r.u8();
  (void)r.u32();
  (void)r.hash16();
  auto part_count = r.u16();
  for(std::uint16_t i = 0; i < part_count; ++i) (void)r.hash16();
  auto tag_count = r.u32();
  std::vector<RawTagHeader> tags;
  for(std::uint32_t i = 0; i < tag_count && r.ok(); ++i) {
    RawTagHeader h;
    auto type = r.u8();
    bool id_name = (type & codec::tagtype::NameFlag) != 0;
    h.type = static_cast<std::uint8_t>(type & ~codec::tagtype::NameFlag);
    if(id_name) h.name_id = r.u8();
    else h.name_str = r.string16();
    switch(h.type) {
      case codec::tagtype::String: (void)r.string16(); break;
      case codec::tagtype::Hash16: (void)r.hash16(); break;
      case codec::tagtype::Uint32: (void)r.u32(); break;
      case codec::tagtype::Uint64: (void)r.u64(); break;
      case codec::tagtype::Blob: {
        auto n = r.u32();
        (void)r.blob(n);
        break;
      }
      default:
        return tags;
    }
    tags.push_back(std::move(h));
  }
  return tags;
}
}

TEST(KnownMet, RoundTrip){
  KnownFileEntry e; e.date=1700000000; e.size=9728010;
  e.hash=*FileHash::from_hex("4127a47867b6110f0f86f2d9845fb374");
  e.part_hashes={ *PartHash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0") };
  auto bytes=write_known_met(std::array<KnownFileEntry,1>{e});
  auto out=parse_known_met(bytes);
  ASSERT_TRUE(out.has_value()); ASSERT_EQ(out->size(),1u);
  EXPECT_EQ((*out)[0].hash, e.hash);
  EXPECT_EQ((*out)[0].part_hashes, e.part_hashes);
  EXPECT_EQ((*out)[0].date, e.date);
}
TEST(PartMet, ParsesAMuleSmallFormat){
  PartFileState p; p.hash=*FileHash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0");
  p.size = PART + 1234;
  p.part_hashes={ *PartHash::from_hex("00112233445566778899aabbccddeeff"),
                  *PartHash::from_hex("ffeeddccbbaa99887766554433221100") };
  p.gaps={ {0,100}, {PART, PART + 1234} };
  auto bytes=make_amule_part_met(PARTFILE_VERSION, p.hash, p.part_hashes, p.size, p.gaps);
  auto out=parse_part_met(bytes);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->hash, p.hash);
  EXPECT_EQ(out->part_hashes, p.part_hashes);
  EXPECT_EQ(out->size, p.size);
  EXPECT_EQ(out->gaps, p.gaps);
}

TEST(PartMet, WriteUsesAMuleFormat){
  PartFileState p; p.hash=*FileHash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0");
  p.size = PART;
  p.gaps={ {0,100}, {500,PART} };
  auto bytes=write_part_met(p);
  ASSERT_FALSE(bytes.empty());
  EXPECT_EQ(std::to_integer<std::uint8_t>(bytes[0]), PARTFILE_VERSION);

  auto tags = raw_part_met_tags(bytes);
  EXPECT_TRUE(std::none_of(tags.begin(), tags.end(), [](const RawTagHeader& t){ return t.name_id == FT_INTERNAL_GAPS; }));
  EXPECT_TRUE(std::any_of(tags.begin(), tags.end(), [](const RawTagHeader& t){
    return t.name_id == FT_FILESIZE && t.type == codec::tagtype::Uint32;
  }));
  auto out=parse_part_met(bytes);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->hash, p.hash);
  EXPECT_EQ(out->size, p.size);
  EXPECT_EQ(out->gaps, p.gaps);
}

TEST(PartMet, WriteLargeAMuleFormatUsesUint64GapTags){
  PartFileState p; p.hash=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  p.size = (std::uint64_t{4} * 1024 * 1024 * 1024) + PART;
  p.gaps={ {p.size - 4096, p.size} };
  auto bytes=write_part_met(p);
  ASSERT_FALSE(bytes.empty());
  EXPECT_EQ(std::to_integer<std::uint8_t>(bytes[0]), PARTFILE_VERSION_LARGEFILE);

  auto tags = raw_part_met_tags(bytes);
  EXPECT_TRUE(std::any_of(tags.begin(), tags.end(), [](const RawTagHeader& t){
    return t.name_id == FT_FILESIZE && t.type == codec::tagtype::Uint64;
  }));
  EXPECT_TRUE(std::any_of(tags.begin(), tags.end(), [](const RawTagHeader& t){
    return !t.name_str.empty() && static_cast<std::uint8_t>(t.name_str[0]) == FT_GAPSTART &&
           t.type == codec::tagtype::Uint64;
  }));
  EXPECT_TRUE(std::any_of(tags.begin(), tags.end(), [](const RawTagHeader& t){
    return !t.name_str.empty() && static_cast<std::uint8_t>(t.name_str[0]) == FT_GAPEND &&
           t.type == codec::tagtype::Uint64;
  }));

  auto out=parse_part_met(bytes);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->size, p.size);
  EXPECT_EQ(out->gaps, p.gaps);
}

TEST(PartMet, LoadsLegacyInternalFormat){
  PartFileState p; p.hash=*FileHash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0");
  p.gaps={ {0,100}, {500,9728000} };
  auto out=parse_part_met(make_legacy_internal_part_met(p));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->hash, p.hash);
  EXPECT_EQ(out->gaps, p.gaps);
  EXPECT_EQ(out->size, 0u);
}
TEST(PartMet, RejectsBadMagic){
  std::array<std::byte,1> b{ std::byte{0x99} };
  EXPECT_FALSE(parse_part_met(b).has_value());
}
TEST(KnownMet, RejectsBadMagic){
  std::array<std::byte,1> b{ std::byte{0x99} };
  EXPECT_FALSE(parse_known_met(b).has_value());
}
