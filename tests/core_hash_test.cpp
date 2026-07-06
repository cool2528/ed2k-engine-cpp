#include <gtest/gtest.h>
#include <functional>
#include <utility>
#include "ed2k/core/hash.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/net/packet.hpp"
using namespace ed2k;

namespace {
constexpr std::array<std::byte,16> zero_md4{};
constexpr std::array<std::byte,20> zero_aich{};
constexpr auto constexpr_md4 = MD4Hash::from_bytes(zero_md4);
constexpr auto constexpr_aich = AICHHash::from_bytes(zero_aich);
constexpr auto localhost = IPv4::from_wire(0x0100007Fu);

static_assert(noexcept(MD4Hash::from_bytes(zero_md4)));
static_assert(noexcept(AICHHash::from_bytes(zero_aich)));
static_assert(noexcept(std::declval<const MD4Hash&>().bytes()));
static_assert(noexcept(std::declval<const AICHHash&>().bytes()));
static_assert(noexcept(IPv4::from_wire(0x0100007Fu)));
static_assert(constexpr_md4.bytes()[0] == std::byte{0});
static_assert(constexpr_aich.bytes()[0] == std::byte{0});
static_assert(localhost.host() == 0x7F000001u);
static_assert(AICH_BLOCK_SIZE == 184320u);
static_assert(PART_SIZE == 9728000u);
static_assert(net::MAX_PACKET_SIZE == 8u * 1024u * 1024u);
}

TEST(MD4Hash, HexRoundTrip){
  auto h = MD4Hash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0");
  ASSERT_TRUE(h.has_value());
  EXPECT_EQ(h->to_hex(), "31d6cfe0d16ae931b73c59d7e0c089c0");
}
TEST(MD4Hash, RejectsBadHex){
  EXPECT_FALSE(MD4Hash::from_hex("xyz").has_value());
  EXPECT_FALSE(MD4Hash::from_hex("31d6").has_value()); // 长度不足
}
TEST(MD4Hash, HashSeparatesWeakPolynomialCollision){
  std::array<std::byte,16> a{};
  std::array<std::byte,16> b{};
  a[1] = std::byte{131};
  b[0] = std::byte{1};
  ASSERT_NE(a, b);
  EXPECT_NE(std::hash<MD4Hash>{}(MD4Hash::from_bytes(a)),
            std::hash<MD4Hash>{}(MD4Hash::from_bytes(b)));
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
