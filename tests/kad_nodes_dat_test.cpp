#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ed2k/codec/byte_io.hpp"
#include "ed2k/kad/nodes_dat.hpp"

using namespace ed2k;
using namespace ed2k::kad;

namespace {
KadID kid(const char* hex) {
  return *KadID::from_hex(hex);
}

void write_amule_contact(codec::ByteWriter& writer, const Contact& contact) {
  const auto wire_id = kad_id_to_uint128_wire(contact.id);
  writer.blob(wire_id);
  writer.u32(contact.ip.host());
  writer.u16(contact.udp_port);
  writer.u16(contact.tcp_port);
  writer.u8(contact.version);
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

TEST(NodesDat, ParsesAmuleVersion2ContactList) {
  const std::vector<Contact> contacts{
      Contact{kid("3322110077665544bbaa9988ffeeddcc"), *IPv4::from_dotted("10.1.2.3"), 4665, 4662, 8},
      Contact{kid("ccddeeff8899aabb4455667700112233"), *IPv4::from_dotted("203.0.113.9"), 14665, 14662, 9},
  };

  codec::ByteWriter writer;
  writer.u32(0);
  writer.u32(2);
  writer.u32(static_cast<std::uint32_t>(contacts.size()));
  for (const auto& contact : contacts) {
    write_amule_contact(writer, contact);
    writer.u32(0x01020304);
    writer.u32(IPv4::from_dotted("198.51.100.7")->host());
    writer.u8(1);
  }

  auto parsed = parse_nodes_dat(writer.take());
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->size(), contacts.size());
  EXPECT_EQ((*parsed)[0], contacts[0]);
  EXPECT_EQ((*parsed)[1], contacts[1]);
}

TEST(NodesDat, ParsesPublicVersion2IpAsKadHostOrder) {
  const auto contact = Contact{
      kid("b9f917ade56b172ead411a3a1b3578bb"),
      *IPv4::from_dotted("218.91.30.199"),
      33396,
      7733,
      10,
  };

  codec::ByteWriter writer;
  writer.u32(0);
  writer.u32(2);
  writer.u32(1);
  write_amule_contact(writer, contact);
  writer.u32(0);
  writer.u32(0);
  writer.u8(0);

  auto parsed = parse_nodes_dat(writer.take());
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->size(), 1u);
  EXPECT_EQ((*parsed)[0], contact);
}

TEST(NodesDat, ParsesAmuleBootstrapEditionContactList) {
  const std::vector<Contact> contacts{
      Contact{kid("3322110077665544bbaa9988ffeeddcc"), *IPv4::from_dotted("10.1.2.3"), 4665, 4662, 8},
  };

  codec::ByteWriter writer;
  writer.u32(0);
  writer.u32(3);
  writer.u32(1);
  writer.u32(static_cast<std::uint32_t>(contacts.size()));
  for (const auto& contact : contacts) {
    write_amule_contact(writer, contact);
  }

  auto parsed = parse_nodes_dat(writer.take());
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->size(), contacts.size());
  EXPECT_EQ((*parsed)[0], contacts[0]);
}
