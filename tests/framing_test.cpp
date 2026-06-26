#include <gtest/gtest.h>
#include <array>
#include <algorithm>
#include "ed2k/net/framing.hpp"
#include "ed2k/util/error.hpp"
#include "net/inflate.hpp"
#include <zlib.h>
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
static std::vector<std::byte> zlib_compress(std::span<const std::byte> in){
  uLongf bound = compressBound(static_cast<uLong>(in.size()));
  std::vector<std::byte> out(bound);
  uLongf outlen = bound;
  compress(reinterpret_cast<Bytef*>(out.data()), &outlen,
           reinterpret_cast<const Bytef*>(in.data()), static_cast<uLong>(in.size()));
  out.resize(outlen);
  return out;
}
TEST(Framing, ZlibPacketDecompressesAndNormalizes){
  auto payload = bytes({10,20,30,40,50});
  auto comp = zlib_compress(payload);
  std::vector<std::byte> body; body.push_back(std::byte{0x16});      // opcode
  body.insert(body.end(), comp.begin(), comp.end());
  auto q = assemble(proto::zlib, body);
  ASSERT_TRUE(q.has_value());
  EXPECT_EQ(q->protocol, proto::eMule);                              // 归一化
  EXPECT_EQ(q->opcode, 0x16);
  EXPECT_EQ(q->payload, payload);
}
TEST(Framing, BadZlibStreamFails){
  auto body = bytes({0x16, 0xFF,0xFF,0xFF,0xFF});                    // opcode + 坏流
  auto q = assemble(proto::zlib, body);
  ASSERT_FALSE(q.has_value());
  EXPECT_EQ(q.error(), make_error_code(errc::decompress_failed));
}
TEST(Inflate, RespectsOutputCap){
  std::vector<std::byte> big(100000, std::byte{0});                  // 压缩极小、解压 100k
  auto comp = zlib_compress(big);
  auto over = zlib_inflate(comp, 1024);                             // 上限 < 100k
  EXPECT_FALSE(over.has_value());
  EXPECT_EQ(over.error(), make_error_code(errc::decompress_failed));
  auto ok = zlib_inflate(comp, 200000);
  ASSERT_TRUE(ok.has_value());
  EXPECT_EQ(ok->size(), big.size());
}
