#include <gtest/gtest.h>

#include <string_view>
#include <vector>

#include "ed2k/net/udp_framing.hpp"
#include "ed2k/net/udp_obfuscation.hpp"
#include "ed2k/server/udp_messages.hpp"

using namespace ed2k;
using namespace ed2k::net;
using namespace ed2k::server;

namespace {
int hex_nibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

std::vector<std::byte> hex_blob(std::string_view hex) {
  std::vector<std::byte> out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    const auto hi = hex_nibble(hex[i]);
    const auto lo = hex_nibble(hex[i + 1]);
    out.push_back(std::byte((hi << 4) | lo));
  }
  return out;
}
} // namespace

TEST(UdpObfuscation, EncodesAmuleServerRequestVector) {
  Packet request;
  request.protocol = proto::eDonkey;
  request.opcode = udpop::GLOBSERVSTATREQ;
  request.payload = encode_server_status_req(0x12345678u);

  auto encoded = encode_server_udp_obfuscated_datagram(
      encode_udp_packet(request),
      ServerUdpObfuscationOptions{
          .base_key = 0x11223344u,
          .direction = ServerUdpObfuscationDirection::client_to_server,
          .random_key_part = 0xbeefu,
          .marker = 0x42,
      });

  ASSERT_TRUE(encoded.has_value());
  EXPECT_EQ(*encoded, hex_blob("42efbed3f4afb3bb3bcbef09f998"));
}

TEST(UdpObfuscation, DecodesAmuleServerResponseVector) {
  auto decoded = decode_server_udp_obfuscated_datagram(
      hex_blob("42efbea90a55109c54cf7b63a47e"),
      ServerUdpObfuscationDecodeOptions{
          .base_key = 0x11223344u,
          .direction = ServerUdpObfuscationDirection::server_to_client,
      });

  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->encrypted);

  auto packet = parse_udp_datagram(decoded->datagram);
  ASSERT_TRUE(packet.has_value());
  EXPECT_EQ(packet->protocol, proto::eDonkey);
  EXPECT_EQ(packet->opcode, udpop::GLOBSERVSTATREQ);
  EXPECT_EQ(packet->payload, encode_server_status_req(0x12345678u));
}

TEST(UdpObfuscation, PlainServerDatagramPassesThroughForFallback) {
  Packet plain;
  plain.protocol = proto::eDonkey;
  plain.opcode = udpop::GLOBSERVSTATREQ;
  plain.payload = encode_server_status_req(0x12345678u);
  auto datagram = encode_udp_packet(plain);

  auto decoded = decode_server_udp_obfuscated_datagram(
      datagram,
      ServerUdpObfuscationDecodeOptions{
          .base_key = 0x11223344u,
          .direction = ServerUdpObfuscationDirection::server_to_client,
      });

  ASSERT_TRUE(decoded.has_value());
  EXPECT_FALSE(decoded->encrypted);
  EXPECT_EQ(decoded->datagram, datagram);
}

