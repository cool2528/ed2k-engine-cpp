#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ed2k/kad/nodes_dat.hpp"

using namespace ed2k;
using namespace ed2k::kad;

namespace {
KadID kid(const char* hex) {
  return *KadID::from_hex(hex);
}
} // namespace

TEST(NodesDat, RoundTripsCompactContactList) {
  std::vector<Contact> contacts{
      Contact{kid("00112233445566778899aabbccddeeff"), *IPv4::from_dotted("10.1.2.3"), 4665, 4662, 8},
      Contact{kid("ffeeddccbbaa99887766554433221100"), *IPv4::from_dotted("203.0.113.9"), 14665, 14662, 9},
  };

  auto bytes = write_nodes_dat(contacts);
  ASSERT_EQ(bytes.size(), 8u + contacts.size() * 25u);
  EXPECT_EQ(std::to_integer<unsigned>(bytes[0]), 'K');
  EXPECT_EQ(std::to_integer<unsigned>(bytes[1]), 'A');
  EXPECT_EQ(std::to_integer<unsigned>(bytes[2]), 'D');
  EXPECT_EQ(std::to_integer<unsigned>(bytes[3]), '2');

  auto parsed = parse_nodes_dat(bytes);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->size(), contacts.size());
  EXPECT_EQ((*parsed)[0], contacts[0]);
  EXPECT_EQ((*parsed)[1], contacts[1]);
}

TEST(NodesDat, RejectsBadMagicAndTruncatedContacts) {
  std::vector<Contact> contacts{
      Contact{kid("00112233445566778899aabbccddeeff"), *IPv4::from_dotted("10.1.2.3"), 4665, 4662, 8},
  };

  auto bytes = write_nodes_dat(contacts);
  bytes[0] = std::byte{'B'};
  EXPECT_FALSE(parse_nodes_dat(bytes).has_value());

  bytes = write_nodes_dat(contacts);
  bytes.pop_back();
  EXPECT_FALSE(parse_nodes_dat(bytes).has_value());
}
