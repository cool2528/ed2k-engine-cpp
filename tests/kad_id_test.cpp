#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "crypto/md4.hpp"
#include "ed2k/kad/kad_id.hpp"

using namespace ed2k;
using namespace ed2k::kad;

TEST(KadID, HexRoundTripAndBitOrder) {
  auto id = KadID::from_hex("80000000000000000000000000000001");
  ASSERT_TRUE(id.has_value());
  EXPECT_EQ(id->to_hex(), "80000000000000000000000000000001");
  EXPECT_EQ(id->bit(0), 1u);
  EXPECT_EQ(id->bit(1), 0u);
  EXPECT_EQ(id->bit(126), 0u);
  EXPECT_EQ(id->bit(127), 1u);

  EXPECT_FALSE(KadID::from_hex("0011").has_value());
  EXPECT_FALSE(KadID::from_hex("00112233445566778899aabbccddeefg").has_value());
}

TEST(KadID, XorDistanceOrdersByBigEndianMagnitude) {
  auto target = *KadID::from_hex("00000000000000000000000000000000");
  auto near = *KadID::from_hex("00000000000000000000000000000001");
  auto far = *KadID::from_hex("80000000000000000000000000000000");

  EXPECT_EQ(xor_distance(target, near).to_hex(), "00000000000000000000000000000001");
  EXPECT_EQ(xor_distance(target, far).to_hex(), "80000000000000000000000000000000");
  EXPECT_TRUE(closer_to_target(near, far, target));
  EXPECT_FALSE(closer_to_target(far, near, target));
}

TEST(KadID, GeneratesFromUserHashAndNonceWithMd4) {
  auto user_hash = *UserHash::from_hex("00112233445566778899aabbccddeeff");
  std::vector<std::byte> seed(user_hash.bytes().begin(), user_hash.bytes().end());
  seed.push_back(std::byte{0x04});
  seed.push_back(std::byte{0x03});
  seed.push_back(std::byte{0x02});
  seed.push_back(std::byte{0x01});

  EXPECT_EQ(KadID::from_user_hash(user_hash, 0x01020304).bytes(), crypto::md4(seed));
  EXPECT_NE(KadID::from_user_hash(user_hash, 0x01020304),
            KadID::from_user_hash(user_hash, 0x01020305));
}
