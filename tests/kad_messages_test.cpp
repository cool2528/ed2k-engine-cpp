#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ed2k/kad/messages.hpp"
#include "ed2k/net/udp_framing.hpp"

using namespace ed2k;
using namespace ed2k::kad;

namespace {
KadID kid(const char* hex) {
  return *KadID::from_hex(hex);
}

Contact contact(const char* id_hex, const char* ip, std::uint16_t udp_port, std::uint16_t tcp_port,
                std::uint8_t version = kad2_version) {
  return Contact{
      .id = kid(id_hex),
      .ip = *IPv4::from_dotted(ip),
      .udp_port = udp_port,
      .tcp_port = tcp_port,
      .version = version,
  };
}

std::vector<unsigned> bytes_of(const std::vector<std::byte>& data) {
  std::vector<unsigned> out;
  out.reserve(data.size());
  for (auto b : data) {
    out.push_back(std::to_integer<unsigned>(b));
  }
  return out;
}
} // namespace

TEST(KadMessages, HelloReqUsesKadProtocolAndAmuleLayout) {
  const auto self = contact("00112233445566778899aabbccddeeff", "10.1.2.3", 4665, 4662, 8);

  auto packet = encode_kad2_hello_req(self);

  EXPECT_EQ(packet.protocol, kad_protocol);
  EXPECT_EQ(packet.opcode, opcode::kad2_hello_req);
  ASSERT_EQ(packet.payload.size(), 20u);
  EXPECT_EQ(bytes_of(packet.payload),
            (std::vector<unsigned>{
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                0x36, 0x12, 0x08, 0x00,
            }));

  auto decoded = decode_kad2_hello(packet, *IPv4::from_dotted("203.0.113.7"), 14665);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->id, self.id);
  EXPECT_EQ(decoded->ip.to_dotted(), "203.0.113.7");
  EXPECT_EQ(decoded->udp_port, 14665);
  EXPECT_EQ(decoded->tcp_port, 0x1236);
  EXPECT_EQ(decoded->version, 8);
}

TEST(KadMessages, ReqAndResRoundTripWithReceiverCheckId) {
  const auto target = kid("0102030405060708090a0b0c0d0e0f10");
  const auto receiver = kid("101112131415161718191a1b1c1d1e1f");
  const auto first = contact("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", 4665, 4662, 8);
  const auto second = contact("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "203.0.113.9", 14665, 14662, 9);

  auto req_packet = encode_kad2_req(target, receiver, 10);
  EXPECT_EQ(req_packet.protocol, kad_protocol);
  EXPECT_EQ(req_packet.opcode, opcode::kad2_req);
  ASSERT_EQ(req_packet.payload.size(), 33u);
  EXPECT_EQ(std::to_integer<unsigned>(req_packet.payload[0]), 10u);

  auto req = decode_kad2_req(req_packet);
  ASSERT_TRUE(req.has_value());
  EXPECT_EQ(req->count, 10u);
  EXPECT_EQ(req->target, target);
  EXPECT_EQ(req->receiver_id, receiver);

  const std::vector<Contact> contacts{first, second};
  auto res_packet = encode_kad2_res(target, contacts);
  EXPECT_EQ(res_packet.protocol, kad_protocol);
  EXPECT_EQ(res_packet.opcode, opcode::kad2_res);
  ASSERT_EQ(res_packet.payload.size(), 67u);
  EXPECT_EQ(std::to_integer<unsigned>(res_packet.payload[16]), 2u);

  auto res = decode_kad2_res(res_packet);
  ASSERT_TRUE(res.has_value());
  ASSERT_EQ(res->contacts.size(), 2u);
  EXPECT_EQ(res->target, target);
  EXPECT_EQ(res->contacts[0].id, first.id);
  EXPECT_EQ(res->contacts[0].ip.to_dotted(), "1.2.3.4");
  EXPECT_EQ(res->contacts[0].udp_port, 4665);
  EXPECT_EQ(res->contacts[0].tcp_port, 4662);
  EXPECT_EQ(res->contacts[0].version, 8);
  EXPECT_EQ(res->contacts[1].ip.to_dotted(), "203.0.113.9");
}

TEST(KadMessages, RejectsMalformedPackets) {
  auto hello = encode_kad2_hello_req(contact("00112233445566778899aabbccddeeff", "10.0.0.1", 4665, 4662));
  hello.protocol = net::proto::eDonkey;
  EXPECT_FALSE(decode_kad2_hello(hello, *IPv4::from_dotted("10.0.0.2"), 4665).has_value());

  auto req = encode_kad2_req(kid("0102030405060708090a0b0c0d0e0f10"),
                             kid("101112131415161718191a1b1c1d1e1f"), 0);
  EXPECT_FALSE(decode_kad2_req(req).has_value());

  net::Packet truncated_res;
  truncated_res.protocol = kad_protocol;
  truncated_res.opcode = opcode::kad2_res;
  truncated_res.payload = {std::byte{0x01}};
  EXPECT_FALSE(decode_kad2_res(truncated_res).has_value());
}
