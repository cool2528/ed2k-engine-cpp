#include <gtest/gtest.h>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>
#include "ed2k/codec/byte_io.hpp"
using namespace ed2k; using namespace ed2k::codec;

static_assert(ByteRange<std::vector<std::byte>>);
static_assert(ByteRange<std::array<std::byte,4>>);
static_assert(ByteRange<std::span<const std::byte>>);
static_assert(!ByteRange<std::vector<std::uint8_t>>);
static_assert(noexcept(std::declval<const ByteReader&>().ok()));
static_assert(noexcept(std::declval<const ByteReader&>().remaining()));
static_assert(noexcept(std::declval<const ByteReader&>().pos()));
static_assert(std::is_same_v<decltype(std::declval<ByteReader&>().u8()), std::uint8_t>);
static_assert(std::is_same_v<decltype(std::declval<ByteReader&>().u16()), std::uint16_t>);
static_assert(std::is_same_v<decltype(std::declval<ByteReader&>().u32()), std::uint32_t>);
static_assert(std::is_same_v<decltype(std::declval<ByteReader&>().u64()), std::uint64_t>);

TEST(ByteIO, RoundTripPrimitives){
  ByteWriter w; w.u8(0x12); w.u16(0x3456); w.u32(0x89abcdef); w.u64(0x1122334455667788ull);
  w.string16("hello");
  auto buf = w.take();
  ByteReader r(buf);
  EXPECT_EQ(r.u8(),0x12); EXPECT_EQ(r.u16(),0x3456); EXPECT_EQ(r.u32(),0x89abcdefu);
  EXPECT_EQ(r.u64(),0x1122334455667788ull); EXPECT_EQ(r.string16(),"hello");
  EXPECT_TRUE(r.ok()); EXPECT_EQ(r.remaining(),0u);
}
TEST(ByteIO, LittleEndianLayout){
  ByteWriter w; w.u32(0x01020304); auto b=w.take();
  ASSERT_EQ(b.size(),4u);
  EXPECT_EQ(std::to_integer<int>(b[0]),0x04); // 小端：低字节在前
  EXPECT_EQ(std::to_integer<int>(b[3]),0x01);
}
TEST(ByteIO, UnderflowSetsNotOk){
  std::array<std::byte,2> tiny{};
  ByteReader r(tiny);
  (void)r.u32();               // 越界
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.u8(),0u);        // 出错后空转返回 0
}
TEST(ByteIO, ByteRangeOverloadsAcceptStdByteContainers){
  std::vector<std::byte> payload{std::byte{0x34}, std::byte{0x12}, std::byte{0xAB}};
  ByteReader r(payload);
  EXPECT_EQ(r.u16(), 0x1234u);
  EXPECT_EQ(r.u8(), 0xABu);

  ByteWriter w;
  w.blob(payload);
  EXPECT_EQ(w.take(), payload);
}
