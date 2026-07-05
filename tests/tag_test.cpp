#include <gtest/gtest.h>
#include "ed2k/codec/tag.hpp"
using namespace ed2k; using namespace ed2k::codec;
static Tag str_tag(std::uint8_t id,std::string v){ Tag t; t.name_id=id; t.value=std::move(v); return t; }
static Tag u32_tag(std::uint8_t id,std::uint64_t v){ Tag t; t.name_id=id; t.value=v; return t; }
static std::vector<std::byte> bytes(std::initializer_list<int> xs){
  std::vector<std::byte> out;
  for(int x:xs) out.push_back(std::byte(x));
  return out;
}
TEST(Tag, StringRoundTrip){
  ByteWriter w; write_tag(w, str_tag(0x01,"servername"));
  auto buf=w.take(); ByteReader r(buf);
  auto t=read_tag(r); ASSERT_TRUE(t.has_value());
  EXPECT_EQ(t->name_id,0x01);
  ASSERT_TRUE(std::holds_alternative<std::string>(t->value));
  EXPECT_EQ(std::get<std::string>(t->value),"servername");
}
TEST(Tag, ListRoundTrip){
  std::vector<Tag> in{ str_tag(0x01,"name"), u32_tag(0x87,12345) };
  ByteWriter w; write_taglist(w,in); auto buf=w.take();
  ByteReader r(buf); auto out=read_taglist(r,2);
  ASSERT_TRUE(out.has_value()); ASSERT_EQ(out->size(),2u);
  EXPECT_EQ(std::get<std::string>((*out)[0].value),"name");
  EXPECT_EQ(std::get<std::uint64_t>((*out)[1].value),12345u);
}
TEST(Tag, TruncatedFails){
  std::array<std::byte,1> tiny{ std::byte{0x03} }; // 声明 u32 但无数据
  ByteReader r(tiny); auto t=read_tag(r); EXPECT_FALSE(t.has_value());
}
TEST(Tag, WriteUint64UsesAmuleTagType){
  Tag in; in.name_id=0x01; in.value=std::uint64_t(0x0102030405060708ull);
  ByteWriter w; write_tag(w, in);
  EXPECT_EQ(w.take(), bytes({0x8B,0x01, 0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01}));
}
TEST(Tag, ReadsAmuleUint64TagType){
  auto buf = bytes({0x8B,0x01, 0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01});
  ByteReader r(buf); auto t=read_tag(r);
  ASSERT_TRUE(t.has_value());
  EXPECT_EQ(t->name_id,0x01);
  ASSERT_TRUE(std::holds_alternative<std::uint64_t>(t->value));
  EXPECT_EQ(std::get<std::uint64_t>(t->value), 0x0102030405060708ull);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.remaining(), 0u);
}
TEST(Tag, ReadsAmuleBlobTagType){
  auto buf = bytes({0x87,0x02, 0x03,0x00,0x00,0x00, 0xAA,0xBB,0xCC});
  ByteReader r(buf); auto t=read_tag(r);
  ASSERT_TRUE(t.has_value());
  EXPECT_EQ(t->name_id,0x02);
  ASSERT_TRUE(std::holds_alternative<std::vector<std::byte>>(t->value));
  EXPECT_EQ(std::get<std::vector<std::byte>>(t->value), bytes({0xAA,0xBB,0xCC}));
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.remaining(), 0u);
}
TEST(Tag, ReadsAmuleBsobTagType){
  auto buf = bytes({0x8A,0x03, 0x02, 0xDE,0xAD});
  ByteReader r(buf); auto t=read_tag(r);
  ASSERT_TRUE(t.has_value());
  EXPECT_EQ(t->name_id,0x03);
  ASSERT_TRUE(std::holds_alternative<std::vector<std::byte>>(t->value));
  EXPECT_EQ(std::get<std::vector<std::byte>>(t->value), bytes({0xDE,0xAD}));
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.remaining(), 0u);
}
TEST(Tag, ReadsAmuleShortStringThroughStr22){
  auto buf = bytes({0xA6,0x04});
  const std::string value = "abcdefghijklmnopqrstuv";
  for(char c:value) buf.push_back(std::byte(static_cast<unsigned char>(c)));
  ByteReader r(buf); auto t=read_tag(r);
  ASSERT_TRUE(t.has_value());
  EXPECT_EQ(t->name_id,0x04);
  ASSERT_TRUE(std::holds_alternative<std::string>(t->value));
  EXPECT_EQ(std::get<std::string>(t->value), value);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.remaining(), 0u);
}
// Regression: Tag now has a defaulted operator<=>, so whole-Tag (in)equality compiles.
TEST(Tag, EqualityCompares){
  Tag a = str_tag(0x01,"name");
  Tag b = str_tag(0x01,"name");
  Tag c = str_tag(0x01,"other");
  EXPECT_EQ(a, b);
  EXPECT_NE(a, c);
}
