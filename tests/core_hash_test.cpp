#include <gtest/gtest.h>
#include "ed2k/core/hash.hpp"
using namespace ed2k;
TEST(MD4Hash, HexRoundTrip){
  auto h = MD4Hash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0");
  ASSERT_TRUE(h.has_value());
  EXPECT_EQ(h->to_hex(), "31d6cfe0d16ae931b73c59d7e0c089c0");
}
TEST(MD4Hash, RejectsBadHex){
  EXPECT_FALSE(MD4Hash::from_hex("xyz").has_value());
  EXPECT_FALSE(MD4Hash::from_hex("31d6").has_value()); // 长度不足
}
TEST(AICHHash, Base32RoundTrip){
  std::array<std::byte,20> raw{}; for(int i=0;i<20;++i) raw[i]=std::byte(i);
  auto a = AICHHash::from_bytes(raw);
  auto b = AICHHash::from_base32(a.to_base32());
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(b->bytes(), raw);
}
TEST(IPv4, DottedRoundTrip){
  auto ip = IPv4::from_dotted("192.168.0.1");
  ASSERT_TRUE(ip.has_value());
  EXPECT_EQ(ip->to_dotted(), "192.168.0.1");
}
TEST(IPv4, RejectsBad){ EXPECT_FALSE(IPv4::from_dotted("999.1.1").has_value()); }
