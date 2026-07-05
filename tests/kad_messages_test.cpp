#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "ed2k/codec/tag.hpp"
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

codec::Tag string_tag(std::uint8_t name_id, std::string value) {
  codec::Tag tag;
  tag.name_str = std::string(1, static_cast<char>(name_id));
  tag.value = std::move(value);
  return tag;
}

codec::Tag int_tag(std::uint8_t name_id, std::uint64_t value) {
  codec::Tag tag;
  tag.name_str = std::string(1, static_cast<char>(name_id));
  tag.value = value;
  return tag;
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

TEST(KadMessages, SearchKeySourceAndResponseRoundTrip) {
  const auto sender = kid("00112233445566778899aabbccddeeff");
  const auto target = kid("0102030405060708090a0b0c0d0e0f10");
  const auto answer = kid("101112131415161718191a1b1c1d1e1f");

  auto key_req_packet = encode_kad2_search_key_req(target, 0);
  EXPECT_EQ(key_req_packet.protocol, kad_protocol);
  EXPECT_EQ(key_req_packet.opcode, opcode::kad2_search_key_req);
  ASSERT_EQ(key_req_packet.payload.size(), 18u);

  auto key_req = decode_kad2_search_key_req(key_req_packet);
  ASSERT_TRUE(key_req.has_value());
  EXPECT_EQ(key_req->target, target);
  EXPECT_EQ(key_req->start_position, 0u);

  auto source_req_packet = encode_kad2_search_source_req(target, 3, 123456789ull);
  EXPECT_EQ(source_req_packet.opcode, opcode::kad2_search_source_req);
  ASSERT_EQ(source_req_packet.payload.size(), 26u);

  auto source_req = decode_kad2_search_source_req(source_req_packet);
  ASSERT_TRUE(source_req.has_value());
  EXPECT_EQ(source_req->target, target);
  EXPECT_EQ(source_req->start_position, 3u);
  EXPECT_EQ(source_req->file_size, 123456789ull);

  const std::vector<KadSearchEntry> entries{KadSearchEntry{
      .answer_id = answer,
      .tags = {string_tag(tag::filename, "ubuntu.iso"), int_tag(tag::file_size, 123456789ull)},
  }};
  auto res_packet = encode_kad2_search_res(sender, target, entries);
  EXPECT_EQ(res_packet.opcode, opcode::kad2_search_res);
  ASSERT_GE(res_packet.payload.size(), 34u);
  EXPECT_EQ(std::to_integer<unsigned>(res_packet.payload[32]), 1u);
  EXPECT_EQ(std::to_integer<unsigned>(res_packet.payload[33]), 0u);

  auto res = decode_kad2_search_res(res_packet);
  ASSERT_TRUE(res.has_value());
  EXPECT_EQ(res->sender_id, sender);
  EXPECT_EQ(res->target, target);
  ASSERT_EQ(res->entries.size(), 1u);
  EXPECT_EQ(res->entries[0].answer_id, answer);
  ASSERT_EQ(res->entries[0].tags.size(), 2u);
}

TEST(KadMessages, PublishKeySourceAndResponseRoundTrip) {
  const auto key = kid("00112233445566778899aabbccddeeff");
  const auto file = kid("0102030405060708090a0b0c0d0e0f10");
  const auto source = kid("101112131415161718191a1b1c1d1e1f");

  const std::vector<KadSearchEntry> files{KadSearchEntry{
      .answer_id = file,
      .tags = {string_tag(tag::filename, "ubuntu.iso"), int_tag(tag::file_size, 123456789ull)},
  }};
  auto key_packet = encode_kad2_publish_key_req(key, files);
  EXPECT_EQ(key_packet.opcode, opcode::kad2_publish_key_req);
  ASSERT_GE(key_packet.payload.size(), 34u);
  EXPECT_EQ(std::to_integer<unsigned>(key_packet.payload[16]), 1u);
  EXPECT_EQ(std::to_integer<unsigned>(key_packet.payload[17]), 0u);

  auto key_req = decode_kad2_publish_key_req(key_packet);
  ASSERT_TRUE(key_req.has_value());
  EXPECT_EQ(key_req->key_id, key);
  ASSERT_EQ(key_req->entries.size(), 1u);
  EXPECT_EQ(key_req->entries[0].answer_id, file);

  const KadSearchEntry source_entry{
      .answer_id = source,
      .tags = {int_tag(tag::source_type, 1), int_tag(tag::source_port, 4662),
               int_tag(tag::source_udp_port, 4665), int_tag(tag::file_size, 123456789ull)},
  };
  auto source_packet = encode_kad2_publish_source_req(file, source_entry);
  EXPECT_EQ(source_packet.opcode, opcode::kad2_publish_source_req);
  ASSERT_GE(source_packet.payload.size(), 33u);

  auto source_req = decode_kad2_publish_source_req(source_packet);
  ASSERT_TRUE(source_req.has_value());
  EXPECT_EQ(source_req->file_id, file);
  EXPECT_EQ(source_req->source.answer_id, source);
  ASSERT_EQ(source_req->source.tags.size(), 4u);

  auto ack_packet = encode_kad2_publish_res(file, 7);
  EXPECT_EQ(ack_packet.opcode, opcode::kad2_publish_res);
  ASSERT_EQ(ack_packet.payload.size(), 17u);

  auto ack = decode_kad2_publish_res(ack_packet);
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(ack->target, file);
  EXPECT_EQ(ack->load, 7u);
}

TEST(KadMessages, SearchAndPublishNotesRoundTrip) {
  const auto file = kid("00112233445566778899aabbccddeeff");
  const auto source = kid("0102030405060708090a0b0c0d0e0f10");

  auto search_packet = encode_kad2_search_notes_req(file, 123456789ull);
  EXPECT_EQ(search_packet.protocol, kad_protocol);
  EXPECT_EQ(search_packet.opcode, opcode::kad2_search_notes_req);
  ASSERT_EQ(search_packet.payload.size(), 24u);

  auto search_req = decode_kad2_search_notes_req(search_packet);
  ASSERT_TRUE(search_req.has_value());
  EXPECT_EQ(search_req->target, file);
  EXPECT_EQ(search_req->file_size, 123456789ull);

  const KadSearchEntry note{
      .answer_id = source,
      .tags = {string_tag(tag::filename, "ubuntu.iso"), string_tag(tag::description, "works"),
               int_tag(tag::file_rating, 4), int_tag(tag::file_size, 123456789ull)},
  };
  auto publish_packet = encode_kad2_publish_notes_req(file, note);
  EXPECT_EQ(publish_packet.opcode, opcode::kad2_publish_notes_req);
  ASSERT_GE(publish_packet.payload.size(), 33u);

  auto publish_req = decode_kad2_publish_notes_req(publish_packet);
  ASSERT_TRUE(publish_req.has_value());
  EXPECT_EQ(publish_req->file_id, file);
  EXPECT_EQ(publish_req->note.answer_id, source);
  ASSERT_EQ(publish_req->note.tags.size(), 4u);
}

TEST(KadMessages, FirewalledAndFirewallUdpUseCurrentAmuleOpcodes) {
  const auto user_hash = kid("00112233445566778899aabbccddeeff");

  auto legacy_req_packet = encode_kademlia_firewalled_req(0x1234);
  EXPECT_EQ(legacy_req_packet.protocol, kad_protocol);
  EXPECT_EQ(legacy_req_packet.opcode, opcode::kademlia_firewalled_req);
  EXPECT_EQ(bytes_of(legacy_req_packet.payload), (std::vector<unsigned>{0x34, 0x12}));

  auto legacy_req = decode_kademlia_firewalled_req(legacy_req_packet);
  ASSERT_TRUE(legacy_req.has_value());
  EXPECT_EQ(legacy_req->tcp_port, 0x1234);

  auto fw2_packet = encode_kademlia_firewalled2_req(0x1234, user_hash, 0x0d);
  EXPECT_EQ(fw2_packet.opcode, opcode::kademlia_firewalled2_req);
  EXPECT_EQ(bytes_of(fw2_packet.payload),
            (std::vector<unsigned>{
                0x34, 0x12,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                0x0d,
            }));

  auto fw2_req = decode_kademlia_firewalled2_req(fw2_packet);
  ASSERT_TRUE(fw2_req.has_value());
  EXPECT_EQ(fw2_req->tcp_port, 0x1234);
  EXPECT_EQ(fw2_req->user_hash, user_hash);
  EXPECT_EQ(fw2_req->connect_options, 0x0d);

  auto res_packet = encode_kademlia_firewalled_res(*IPv4::from_dotted("203.0.113.9"));
  EXPECT_EQ(res_packet.opcode, opcode::kademlia_firewalled_res);
  EXPECT_EQ(bytes_of(res_packet.payload), (std::vector<unsigned>{0xcb, 0x00, 0x71, 0x09}));

  auto res = decode_kademlia_firewalled_res(res_packet);
  ASSERT_TRUE(res.has_value());
  EXPECT_EQ(res->ip.to_dotted(), "203.0.113.9");

  auto ack_packet = encode_kademlia_firewalled_ack_res();
  EXPECT_EQ(ack_packet.opcode, opcode::kademlia_firewalled_ack_res);
  EXPECT_TRUE(ack_packet.payload.empty());
  EXPECT_TRUE(decode_kademlia_firewalled_ack_res(ack_packet).has_value());

  auto udp_packet = encode_kad2_firewall_udp(0, 4665);
  EXPECT_EQ(udp_packet.opcode, opcode::kad2_firewall_udp);
  EXPECT_EQ(bytes_of(udp_packet.payload), (std::vector<unsigned>{0x00, 0x39, 0x12}));

  auto udp = decode_kad2_firewall_udp(udp_packet);
  ASSERT_TRUE(udp.has_value());
  EXPECT_EQ(udp->error_code, 0u);
  EXPECT_EQ(udp->incoming_port, 4665);
}

TEST(KadMessages, FindBuddyAndCallbackUseAmuleKad1Frames) {
  const auto buddy_id = kid("ffeeddccbbaa99887766554433221100");
  const auto user_hash = kid("00112233445566778899aabbccddeeff");
  const auto file_id = kid("0102030405060708090a0b0c0d0e0f10");

  auto req_packet = encode_kademlia_find_buddy_req(buddy_id, user_hash, 0x1234);
  EXPECT_EQ(req_packet.protocol, kad_protocol);
  EXPECT_EQ(req_packet.opcode, opcode::kademlia_find_buddy_req);
  ASSERT_EQ(req_packet.payload.size(), 34u);

  auto req = decode_kademlia_find_buddy_req(req_packet);
  ASSERT_TRUE(req.has_value());
  EXPECT_EQ(req->buddy_id, buddy_id);
  EXPECT_EQ(req->user_hash, user_hash);
  EXPECT_EQ(req->tcp_port, 0x1234);
  EXPECT_FALSE(req->has_connect_options);

  auto res_packet = encode_kademlia_find_buddy_res(buddy_id, user_hash, 0x2345, 0x08);
  EXPECT_EQ(res_packet.opcode, opcode::kademlia_find_buddy_res);
  ASSERT_EQ(res_packet.payload.size(), 35u);

  auto res = decode_kademlia_find_buddy_res(res_packet);
  ASSERT_TRUE(res.has_value());
  EXPECT_EQ(res->buddy_id, buddy_id);
  EXPECT_EQ(res->user_hash, user_hash);
  EXPECT_EQ(res->tcp_port, 0x2345);
  EXPECT_TRUE(res->has_connect_options);
  EXPECT_EQ(res->connect_options, 0x08);

  auto callback_packet = encode_kademlia_callback_req(buddy_id, file_id, 0x3456);
  EXPECT_EQ(callback_packet.opcode, opcode::kademlia_callback_req);
  ASSERT_EQ(callback_packet.payload.size(), 34u);

  auto callback = decode_kademlia_callback_req(callback_packet);
  ASSERT_TRUE(callback.has_value());
  EXPECT_EQ(callback->buddy_id, buddy_id);
  EXPECT_EQ(callback->file_id, file_id);
  EXPECT_EQ(callback->tcp_port, 0x3456);
}

TEST(KadMessages, RejectsMalformedFirewalledBuddyAndCallbackPackets) {
  net::Packet too_short;
  too_short.protocol = kad_protocol;
  too_short.opcode = opcode::kademlia_firewalled2_req;
  too_short.payload = {std::byte{0x34}, std::byte{0x12}};
  EXPECT_FALSE(decode_kademlia_firewalled2_req(too_short).has_value());

  auto wrong_opcode = encode_kad2_firewall_udp(0, 4665);
  wrong_opcode.opcode = opcode::kad2_pong;
  EXPECT_FALSE(decode_kad2_firewall_udp(wrong_opcode).has_value());

  net::Packet nonempty_ack;
  nonempty_ack.protocol = kad_protocol;
  nonempty_ack.opcode = opcode::kademlia_firewalled_ack_res;
  nonempty_ack.payload = {std::byte{0x00}};
  EXPECT_FALSE(decode_kademlia_firewalled_ack_res(nonempty_ack).has_value());

  net::Packet short_callback;
  short_callback.protocol = kad_protocol;
  short_callback.opcode = opcode::kademlia_callback_req;
  short_callback.payload = {std::byte{0x00}};
  EXPECT_FALSE(decode_kademlia_callback_req(short_callback).has_value());
}
