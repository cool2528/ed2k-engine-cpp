#include <gtest/gtest.h>

#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "ed2k/kad/routing_table.hpp"

using namespace ed2k;
using namespace ed2k::kad;

namespace {
KadID kid(const char* hex) {
  return *KadID::from_hex(hex);
}

Contact contact(const char* id_hex, const char* ip, std::uint16_t udp_port) {
  return Contact{
      .id = kid(id_hex),
      .ip = *IPv4::from_dotted(ip),
      .udp_port = udp_port,
      .tcp_port = static_cast<std::uint16_t>(udp_port + 1000),
      .version = 8,
  };
}
} // namespace

TEST(KBucket, AddsAndUpdatesLruOrder) {
  KBucket bucket;
  auto first = contact("00000000000000000000000000000001", "10.0.0.1", 4001);
  auto second = contact("00000000000000000000000000000002", "10.0.0.2", 4002);
  ASSERT_TRUE(bucket.add_or_update(first));
  ASSERT_TRUE(bucket.add_or_update(second));

  first.ip = *IPv4::from_dotted("10.0.0.9");
  first.udp_port = 4999;
  ASSERT_TRUE(bucket.add_or_update(first));

  ASSERT_EQ(bucket.contacts().size(), 2u);
  EXPECT_EQ(bucket.contacts()[0].id, second.id);
  EXPECT_EQ(bucket.contacts()[1].id, first.id);
  EXPECT_EQ(bucket.contacts()[1].ip.to_dotted(), "10.0.0.9");
  EXPECT_EQ(bucket.contacts()[1].udp_port, 4999);
}

TEST(RoutingTable, DoesNotSplitFullBucketOutsideLocalIdRange) {
  RoutingTable table(kid("00000000000000000000000000000000"));

  for (int i = 0; i < 10; ++i) {
    auto hex = "8000000000000000000000000000000" + std::to_string(i);
    ASSERT_TRUE(table.add_or_update(contact(hex.c_str(), "10.0.1.1", static_cast<std::uint16_t>(4100 + i))));
  }
  EXPECT_EQ(table.size(), 10u);
  EXPECT_EQ(table.leaf_count(), 1u);

  EXPECT_FALSE(table.add_or_update(contact("8000000000000000000000000000000a", "10.0.1.99", 4199)));
  EXPECT_EQ(table.size(), 10u);
  EXPECT_EQ(table.leaf_count(), 2u);

  EXPECT_TRUE(table.add_or_update(contact("00000000000000000000000000000001", "10.0.2.1", 4201)));
  EXPECT_EQ(table.size(), 11u);
}

TEST(RoutingTable, SplitsLocalIdSideAndMergesWhenSparse) {
  RoutingTable table(kid("00000000000000000000000000000000"));
  std::vector<KadID> added;

  for (int i = 1; i <= 11; ++i) {
    char id[33]{};
    std::snprintf(id, sizeof(id), "000000000000000000000000000000%02x", i);
    auto c = contact(id, "10.0.3.1", static_cast<std::uint16_t>(4300 + i));
    added.push_back(c.id);
    ASSERT_TRUE(table.add_or_update(c));
  }

  EXPECT_EQ(table.size(), 11u);
  EXPECT_GT(table.leaf_count(), 2u);

  for (std::size_t i = 0; i < 7; ++i) {
    EXPECT_TRUE(table.remove(added[i]));
  }

  EXPECT_EQ(table.size(), 4u);
  EXPECT_EQ(table.leaf_count(), 1u);
}

TEST(RoutingTable, ClosestToReturnsContactsByXorDistance) {
  RoutingTable table(kid("ffffffffffffffffffffffffffffffff"));
  ASSERT_TRUE(table.add_or_update(contact("00000000000000000000000000000008", "10.0.4.8", 4408)));
  ASSERT_TRUE(table.add_or_update(contact("00000000000000000000000000000001", "10.0.4.1", 4401)));
  ASSERT_TRUE(table.add_or_update(contact("00000000000000000000000000000003", "10.0.4.3", 4403)));
  ASSERT_TRUE(table.add_or_update(contact("00000000000000000000000000000002", "10.0.4.2", 4402)));

  auto closest = table.closest_to(kid("00000000000000000000000000000000"), 3);
  ASSERT_EQ(closest.size(), 3u);
  EXPECT_EQ(closest[0].id.to_hex(), "00000000000000000000000000000001");
  EXPECT_EQ(closest[1].id.to_hex(), "00000000000000000000000000000002");
  EXPECT_EQ(closest[2].id.to_hex(), "00000000000000000000000000000003");
}
