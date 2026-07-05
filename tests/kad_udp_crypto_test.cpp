#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <span>
#include <string_view>
#include <vector>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "ed2k/kad/network.hpp"
#include "ed2k/kad/udp_crypto.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/udp_framing.hpp"

using namespace ed2k;
using namespace ed2k::kad;
namespace asio = boost::asio;
using udp = asio::ip::udp;
using namespace std::chrono_literals;

namespace {
template <class F>
void run_coro(net::IoRuntime& rt, F&& body) {
  bool done = false;
  asio::co_spawn(
      rt.context(),
      [&]() -> asio::awaitable<void> {
        co_await body();
        done = true;
        co_return;
      },
      [&](std::exception_ptr e) {
        rt.stop();
        if (e) {
          std::rethrow_exception(e);
        }
      });
  rt.run();
  rt.restart();
  EXPECT_TRUE(done);
}

KadID kid(const char* hex) {
  return *KadID::from_hex(hex);
}

IPv4 loopback_ip() {
  return *IPv4::from_dotted("127.0.0.1");
}

std::vector<std::byte> clear_bootstrap_datagram() {
  return net::encode_udp_packet(net::Packet{kad_protocol, opcode::kad2_bootstrap_req, {}});
}

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

TEST(KadUdpCrypto, ObfuscatedRequestDecryptsWithTargetNodeId) {
  const auto target = kid("00112233445566778899aabbccddeeff");
  const auto clear = clear_bootstrap_datagram();

  auto encoded = encode_kad_obfuscated_datagram(clear, KadUdpEncryptOptions{
                                                           .target_id = target,
                                                           .sender_verify_key = 0x01020304,
                                                           .random_key_part = 0x1122,
                                                           .marker = 0x04,
                                                       });
  ASSERT_TRUE(encoded.has_value());
  ASSERT_EQ(encoded->size(), clear.size() + 16u);
  EXPECT_NE((*encoded)[0], std::byte{kad_protocol});
  EXPECT_EQ(std::to_integer<unsigned>((*encoded)[0]) & 0x03u, 0x00u);

  auto decoded = decode_kad_obfuscated_datagram(*encoded, target, 0);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->encrypted);
  EXPECT_FALSE(decoded->valid_receiver_key);
  EXPECT_EQ(decoded->receiver_verify_key, 0u);
  EXPECT_EQ(decoded->sender_verify_key, 0x01020304u);
  EXPECT_EQ(decoded->datagram, clear);
}

TEST(KadUdpCrypto, TargetNodeKeyUsesAmuleCryptValueChunkOrder) {
  const auto target = kid("00112233445566778899aabbccddeeff");

  EXPECT_EQ(kad_id_crypt_bytes(target),
            (std::array<std::byte, 16>{
                std::byte{0x33}, std::byte{0x22}, std::byte{0x11}, std::byte{0x00},
                std::byte{0x77}, std::byte{0x66}, std::byte{0x55}, std::byte{0x44},
                std::byte{0xbb}, std::byte{0xAA}, std::byte{0x99}, std::byte{0x88},
                std::byte{0xff}, std::byte{0xee}, std::byte{0xdd}, std::byte{0xcc},
            }));
}

TEST(KadUdpCrypto, DecodesAmuleTargetIdObfuscatedHelloResponse) {
  const auto local_id = kid("6019492e24ea22d737037bc7e81e3678");
  const std::vector<std::byte> datagram{
      std::byte{0x54}, std::byte{0x42}, std::byte{0x46}, std::byte{0x03},
      std::byte{0x9b}, std::byte{0x3a}, std::byte{0xe5}, std::byte{0xb6},
      std::byte{0x43}, std::byte{0xaa}, std::byte{0x9e}, std::byte{0x34},
      std::byte{0x61}, std::byte{0xd4}, std::byte{0xb1}, std::byte{0xa3},
      std::byte{0xc1}, std::byte{0x4d}, std::byte{0x95}, std::byte{0x64},
      std::byte{0x31}, std::byte{0xc6}, std::byte{0x29}, std::byte{0xb3},
      std::byte{0xa8}, std::byte{0x64}, std::byte{0x74}, std::byte{0x20},
      std::byte{0xba}, std::byte{0x86}, std::byte{0xda}, std::byte{0xc7},
      std::byte{0x97}, std::byte{0x4a}, std::byte{0xb8}, std::byte{0x36},
      std::byte{0xa5}, std::byte{0xad}, std::byte{0xfd}, std::byte{0x4d},
      std::byte{0x34}, std::byte{0x2e}, std::byte{0xa4},
  };

  auto decoded = decode_kad_obfuscated_datagram(datagram, local_id, 0);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->encrypted);
  EXPECT_EQ(decoded->receiver_verify_key, 0u);
  EXPECT_EQ(decoded->sender_verify_key, 0x451e01eeu);

  auto packet = net::parse_udp_datagram(decoded->datagram);
  ASSERT_TRUE(packet.has_value());
  EXPECT_EQ(packet->protocol, kad_protocol);
  EXPECT_EQ(packet->opcode, opcode::kad2_hello_res);
}

TEST(KadUdpCrypto, DecodesPublicReceiverKeyObfuscatedBootstrapResponse) {
  const auto sender_ip = *IPv4::from_dotted("218.91.30.199");
  const auto datagram = hex_blob(
      "86847321be3b036f7d4436b7a062076a0267b94ea797da73d2ed4d2617441b09"
      "2b29677a07ddcc08dba119f48b80dbf4198edbfdc39e0b32a7a526f5d120461"
      "914d1055af80587545f1b4d342cea8c6e1b749fe12aa4a389ec801f9d7a0e"
      "c7e726eaac91585e86aed9b83cbde6ac49f1d32db13d2d2e7d1c0fc88a08"
      "9e050ea1ca0d4de503c8bbe5d90fb6d6adf85714f1f7643dea9481550e71"
      "9f105c3c6b1307176dcfdd1c79797a36ea0f98197fa459ff818deabafbe32"
      "41e589ab77eb9943fc18930868fb7d4564e4ce26509b0af87adbfdcad9ee4"
      "1660dd929be65e5de04d4a5aa18c46d02f75cff7a72e5c9ffe22de3f9984"
      "908b3371f0c927a77efb649a2521a60077cb8a42b72a8fdd6648a99f12d44"
      "4e476b9b9c571d1f72366950411689674021c37c673aefa6ceb175ff78e10"
      "2a5427700f895d7700ac769e7227b28a38d3ad2ff3d02a72c618f53be5d5"
      "54e04b02e76a463a35a1cf979a935ff044e3118e17bb0855673e2425429ef"
      "a29151ca32cb442d79d2c2d9c609724d23e34944da2fc2427a6527ab9f2c"
      "5ff9289db2dd1655b26c573354e434b06a7249c0720542ff2aba7ddf08155"
      "e0c8e2f2da01cbf455742fabc917bea106ea80db50447e69ac590f980d9b"
      "56e13c7527362bffeab9d07578cfa4d1bffd9b1d092e14cc0755dcc0716c"
      "62c7b5a400394a5dff6d3ba1e044839b879e087d55005876b8aad546e89"
      "fceac0b6e20ee718442e65d4d4aae4d6fb6678d434d88");

  auto decoded = decode_kad_obfuscated_datagram(
      datagram, kid("00112233445566778899aabbccddeeff"),
      kad_udp_verify_key(0x4b414432, sender_ip));
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->encrypted);
  EXPECT_TRUE(decoded->valid_receiver_key);
  EXPECT_EQ(decoded->receiver_verify_key, kad_udp_verify_key(0x4b414432, sender_ip));

  auto packet = net::parse_udp_datagram(decoded->datagram);
  ASSERT_TRUE(packet.has_value());
  EXPECT_EQ(packet->protocol, kad_protocol);
  EXPECT_EQ(packet->opcode, opcode::kad2_bootstrap_res);

  auto response = decode_kad2_bootstrap_res(*packet, sender_ip, 33396);
  ASSERT_TRUE(response.has_value()) << (response ? "" : response.error().message());
  EXPECT_EQ(response->contacts.size(), 20u);
  EXPECT_EQ(response->contacts[0].ip.to_dotted(), "116.234.37.93");
  EXPECT_EQ(response->contacts[0].udp_port, 4672);
  EXPECT_EQ(response->contacts[0].tcp_port, 4662);
  EXPECT_EQ(response->contacts[0].version, 8);
}

TEST(KadUdpCrypto, ObfuscatedResponseDecryptsWithReceiverVerifyKey) {
  const auto self = kid("00112233445566778899aabbccddeeff");
  const auto clear = clear_bootstrap_datagram();

  auto encoded = encode_kad_obfuscated_datagram(clear, KadUdpEncryptOptions{
                                                           .receiver_verify_key = 0xaabbccdd,
                                                           .sender_verify_key = 0x01020304,
                                                           .random_key_part = 0x3344,
                                                           .marker = 0x06,
                                                       });
  ASSERT_TRUE(encoded.has_value());
  ASSERT_EQ(encoded->size(), clear.size() + 16u);
  EXPECT_EQ(std::to_integer<unsigned>((*encoded)[0]) & 0x03u, 0x02u);

  auto decoded = decode_kad_obfuscated_datagram(*encoded, self, 0xaabbccdd);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->encrypted);
  EXPECT_TRUE(decoded->valid_receiver_key);
  EXPECT_EQ(decoded->receiver_verify_key, 0xaabbccddu);
  EXPECT_EQ(decoded->sender_verify_key, 0x01020304u);
  EXPECT_EQ(decoded->datagram, clear);
}

TEST(KadNetwork, BootstrapToVersionSixSeedUsesObfuscatedKadUdp) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork joining(rt.executor(), KadNetworkOptions{
                                          .id = kid("00000000000000000000000000000001"),
                                          .ip = loopback_ip(),
                                          .tcp_port = 5715,
                                          .version = kad2_version,
                                          .kad_udp_key = 0x10203040,
                                      });
    udp::socket raw_seed(rt.context(), udp::endpoint(asio::ip::address_v4::loopback(), 0));
    std::array<std::byte, 1500> buffer{};
    udp::endpoint sender;
    std::vector<std::byte> received;

    asio::co_spawn(
        rt.context(),
        [&]() -> asio::awaitable<void> {
          auto [ec, n] = co_await raw_seed.async_receive_from(
              asio::buffer(buffer), sender, asio::cancel_after(1s, asio::as_tuple(asio::use_awaitable)));
          EXPECT_FALSE(ec);
          received.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(n));
          co_return;
        },
        asio::detached);

    Contact seed{
        .id = kid("00000000000000000000000000000002"),
        .ip = loopback_ip(),
        .udp_port = raw_seed.local_endpoint().port(),
        .tcp_port = 5716,
        .version = 6,
    };
    auto bootstrapped = co_await joining.bootstrap(std::span<const Contact>(&seed, 1), 30ms);
    EXPECT_FALSE(bootstrapped.has_value());

    EXPECT_FALSE(received.empty());
    if (received.empty()) {
      co_return;
    }
    EXPECT_NE(received[0], std::byte{kad_protocol});

    auto decoded = decode_kad_obfuscated_datagram(received, seed.id, 0);
    EXPECT_TRUE(decoded.has_value());
    if (!decoded) {
      co_return;
    }
    EXPECT_TRUE(decoded->encrypted);
    auto packet = net::parse_udp_datagram(decoded->datagram);
    EXPECT_TRUE(packet.has_value());
    if (!packet) {
      co_return;
    }
    EXPECT_EQ(packet->protocol, kad_protocol);
    EXPECT_EQ(packet->opcode, opcode::kad2_bootstrap_req);
    co_return;
  });
}
