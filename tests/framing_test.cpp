#include <gtest/gtest.h>
#include <array>
#include <algorithm>
#include "ed2k/net/framing.hpp"
#include "ed2k/util/error.hpp"
using namespace ed2k; using namespace ed2k::net;
static std::vector<std::byte> bytes(std::initializer_list<int> xs){
  std::vector<std::byte> v; for(int x:xs) v.push_back(std::byte(x)); return v;
}
TEST(Framing, EncodeDecodeRoundTrip){
  Packet p; p.protocol=proto::eMule; p.opcode=0x16; p.payload=bytes({1,2,3,4});
  auto frame=encode_frame(p);
  ASSERT_EQ(frame.size(), 10u);              // 5 头 + size(5)
  std::array<std::byte,5> hdr; std::copy_n(frame.begin(),5,hdr.begin());
  auto h=parse_header(hdr); ASSERT_TRUE(h.has_value());
  EXPECT_EQ(h->protocol, proto::eMule);
  EXPECT_EQ(h->size, 5u);                     // opcode + 4 payload
  std::span<const std::byte> body(frame.data()+5, h->size);
  auto q=assemble(h->protocol, body); ASSERT_TRUE(q.has_value());
  EXPECT_EQ(*q, p);
}
TEST(Framing, LittleEndianSize){
  Packet p; p.opcode=0x01; p.payload.resize(0x0102, std::byte{0});  // size = 0x0103
  auto f=encode_frame(p);
  EXPECT_EQ(std::to_integer<int>(f[1]), 0x03);
  EXPECT_EQ(std::to_integer<int>(f[2]), 0x01);
  EXPECT_EQ(std::to_integer<int>(f[3]), 0x00);
  EXPECT_EQ(std::to_integer<int>(f[4]), 0x00);
}
TEST(Framing, ZeroSizeRejected){
  std::array<std::byte,5> hdr{ std::byte{0xE3}, std::byte{0},std::byte{0},std::byte{0},std::byte{0} };
  auto h=parse_header(hdr);
  ASSERT_FALSE(h.has_value());
  EXPECT_EQ(h.error(), make_error_code(errc::buffer_underflow));
}
TEST(Framing, OversizeRejected){
  std::array<std::byte,5> hdr{ std::byte{0xE3}, std::byte{0xFF},std::byte{0xFF},std::byte{0xFF},std::byte{0xFF} };
  auto h=parse_header(hdr);
  ASSERT_FALSE(h.has_value());
  EXPECT_EQ(h.error(), make_error_code(errc::packet_too_large));
}
TEST(Framing, EmptyBodyRejected){
  auto q=assemble(proto::eDonkey, {});
  EXPECT_FALSE(q.has_value());
}
