#include <gtest/gtest.h>
#include <zlib.h>
#include "ed2k/net/udp_framing.hpp"
#include "ed2k/net/packet.hpp"
#include "ed2k/util/error.hpp"
using namespace ed2k; using namespace ed2k::net;
static std::vector<std::byte> bytes(std::initializer_list<int> xs){
  std::vector<std::byte> v; for(int x:xs) v.push_back(std::byte(x)); return v;
}
static std::vector<std::byte> zlib_compress(std::span<const std::byte> in){
  uLongf bound = compressBound(static_cast<uLong>(in.size()));
  std::vector<std::byte> out(bound); uLongf outlen = bound;
  compress(reinterpret_cast<Bytef*>(out.data()), &outlen,
           reinterpret_cast<const Bytef*>(in.data()), static_cast<uLong>(in.size()));
  out.resize(outlen); return out;
}
TEST(UdpFraming, EncodeHasNoSizeField){
  Packet p; p.protocol=proto::eDonkey; p.opcode=0x92; p.payload=bytes({1,2,3});
  auto out = encode_udp_packet(p);
  ASSERT_EQ(out.size(), 5u);                 // 1 protocol + 1 opcode + 3 payload, 无 4B size
  EXPECT_EQ(std::to_integer<int>(out[0]), 0xE3);
  EXPECT_EQ(std::to_integer<int>(out[1]), 0x92);
}
TEST(UdpFraming, ParseRoundTrip){
  Packet p; p.protocol=proto::eDonkey; p.opcode=0x99; p.payload=bytes({4,5});
  auto r = parse_udp_datagram(encode_udp_packet(p));
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->protocol, proto::eDonkey);
  EXPECT_EQ(r->opcode, 0x99);
  EXPECT_EQ(r->payload, p.payload);
}
TEST(UdpFraming, ZlibInflatesAndNormalizes){
  auto plain = bytes({10,20,30,40,50});
  auto comp = zlib_compress(plain);
  std::vector<std::byte> dg; dg.push_back(std::byte(proto::zlib)); dg.push_back(std::byte(0x99));
  dg.insert(dg.end(), comp.begin(), comp.end());
  auto r = parse_udp_datagram(dg);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->protocol, proto::eMule);      // 归一化
  EXPECT_EQ(r->opcode, 0x99);
  EXPECT_EQ(r->payload, plain);
}
TEST(UdpFraming, KadPackedInflatesAndNormalizes){
  auto plain = bytes({0xB9,0xF9,0x17,0xAD,0xE5,0x6B,0x17,0x2E});
  auto comp = zlib_compress(plain);
  std::vector<std::byte> dg; dg.push_back(std::byte(0xE5)); dg.push_back(std::byte(0x09));
  dg.insert(dg.end(), comp.begin(), comp.end());
  auto r = parse_udp_datagram(dg);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->protocol, 0xE4);
  EXPECT_EQ(r->opcode, 0x09);
  EXPECT_EQ(r->payload, plain);
}
TEST(UdpFraming, BadZlibFails){
  std::vector<std::byte> dg = bytes({proto::zlib, 0x99, 0xFF,0xFF,0xFF,0xFF});
  auto r = parse_udp_datagram(dg);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error(), make_error_code(errc::decompress_failed));
}
TEST(UdpFraming, EmptyDatagramRejected){
  auto r = parse_udp_datagram({});
  EXPECT_FALSE(r.has_value());
  EXPECT_EQ(r.error(), make_error_code(errc::buffer_underflow));
}
