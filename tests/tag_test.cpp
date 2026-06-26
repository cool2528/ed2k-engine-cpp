#include <gtest/gtest.h>
#include "ed2k/codec/tag.hpp"
using namespace ed2k; using namespace ed2k::codec;
static Tag str_tag(std::uint8_t id,std::string v){ Tag t; t.name_id=id; t.value=std::move(v); return t; }
static Tag u32_tag(std::uint8_t id,std::uint64_t v){ Tag t; t.name_id=id; t.value=v; return t; }
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
