#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <string_view>
#include <vector>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include "ed2k/core/hash.hpp"
#include "ed2k/crypto/md5.hpp"
#include "ed2k/crypto/rc4.hpp"
#include "ed2k/net/encrypted_stream_socket.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/util/error.hpp"
#include "mock_peer.hpp"

using namespace std::chrono_literals;
using namespace ed2k;
using namespace ed2k::net;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace {
template <class F>
void run_coro(IoRuntime& rt, F&& body) {
  bool done = false;
  asio::co_spawn(rt.context(),
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

UserHash user_hash() {
  return *UserHash::from_hex("0123456789abcdeffedcba9876543210");
}

TcpObfuscationOptions deterministic_options() {
  TcpObfuscationOptions options;
  options.marker = std::byte{0x42};
  options.random_key_part = 0x01020304u;
  options.random_padding = false;
  options.padding = {std::byte{0xaa}, std::byte{0xbb}};
  return options;
}

void append_u32_le(std::vector<std::byte>& out, std::uint32_t value) {
  out.push_back(std::byte(value & 0xffu));
  out.push_back(std::byte((value >> 8) & 0xffu));
  out.push_back(std::byte((value >> 16) & 0xffu));
  out.push_back(std::byte((value >> 24) & 0xffu));
}

std::vector<std::byte> hex_bytes(std::string_view hex) {
  auto nybble = [](char c) -> unsigned {
    return c <= '9' ? static_cast<unsigned>(c - '0')
                    : static_cast<unsigned>((c | 0x20) - 'a' + 10);
  };

  std::vector<std::byte> out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(std::byte((nybble(hex[i]) << 4) | nybble(hex[i + 1])));
  }
  return out;
}

ed2k::crypto::RC4 amule_tcp_rc4(const UserHash& hash, std::uint8_t role_magic,
                                std::uint32_t random_key_part) {
  std::array<std::byte, 21> key_data{};
  std::copy(hash.bytes().begin(), hash.bytes().end(), key_data.begin());
  key_data[16] = std::byte{role_magic};
  key_data[17] = std::byte(random_key_part & 0xffu);
  key_data[18] = std::byte((random_key_part >> 8) & 0xffu);
  key_data[19] = std::byte((random_key_part >> 16) & 0xffu);
  key_data[20] = std::byte((random_key_part >> 24) & 0xffu);

  ed2k::crypto::RC4 rc4(ed2k::crypto::md5(key_data));
  rc4.discard(1024);
  return rc4;
}

std::vector<std::byte> encrypted_bad_magic_request(const UserHash& target_hash) {
  constexpr std::uint32_t k_random = 0x01020304u;
  auto rc4 = amule_tcp_rc4(target_hash, 34, k_random);

  std::vector<std::byte> out{std::byte{0x42}};
  append_u32_le(out, k_random);

  std::vector<std::byte> encrypted;
  append_u32_le(encrypted, 0x01020304u);
  encrypted.push_back(std::byte{0x00});
  encrypted.push_back(std::byte{0x00});
  encrypted.push_back(std::byte{0x00});
  rc4.process(encrypted);
  out.insert(out.end(), encrypted.begin(), encrypted.end());
  return out;
}
} // namespace

TEST(EncryptedStreamSocket, InitiatorSendsAmuleClearMarkerAndRandomKeyPrefix) {
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void> {
    std::array<std::byte, 5> prefix{};
    auto [ec, n] = co_await asio::async_read(s, asio::buffer(prefix), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec);
    EXPECT_EQ(n, prefix.size());
    EXPECT_EQ(prefix[0], std::byte{0x42});
    EXPECT_EQ(prefix[1], std::byte{0x04});
    EXPECT_EQ(prefix[2], std::byte{0x03});
    EXPECT_EQ(prefix[3], std::byte{0x02});
    EXPECT_EQ(prefix[4], std::byte{0x01});
    boost::system::error_code ignored;
    s.close(ignored);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    EncryptedStreamSocket socket(rt.executor());
    auto connected = co_await socket.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(connected.has_value());
    if (!connected) {
      co_return;
    }
    auto handshake = co_await socket.handshake_initiator(user_hash(), 500ms, deterministic_options());
    EXPECT_FALSE(handshake.has_value());
    socket.close();
    co_return;
  });
}

TEST(EncryptedStreamSocket, InitiatorMatchesAmuleDeterministicHandshakeBytes) {
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void> {
    std::array<std::byte, 14> request{};
    auto [ec, n] = co_await asio::async_read(s, asio::buffer(request), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec);
    EXPECT_EQ(n, request.size());
    EXPECT_EQ(std::vector<std::byte>(request.begin(), request.end()),
              hex_bytes("42040302018af93c49e99c1547bc"));
    boost::system::error_code ignored;
    s.close(ignored);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    EncryptedStreamSocket socket(rt.executor());
    auto connected = co_await socket.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(connected.has_value());
    if (!connected) {
      co_return;
    }
    auto handshake = co_await socket.handshake_initiator(user_hash(), 500ms, deterministic_options());
    EXPECT_FALSE(handshake.has_value());
    socket.close();
    co_return;
  });
}

TEST(EncryptedStreamSocket, AcceptorRejectsPlainProtocolMarker) {
  IoRuntime rt;
  bool checked = false;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void> {
    EncryptedStreamSocket socket(std::move(s));
    auto handshake = co_await socket.handshake_acceptor(user_hash(), 2s, deterministic_options());
    EXPECT_FALSE(handshake.has_value());
    if (!handshake) {
      EXPECT_EQ(handshake.error(), make_error_code(errc::bad_magic));
    }
    checked = true;
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    tcp::socket raw(rt.context());
    auto [connect_ec] = co_await raw.async_connect(
        tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()),
        asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(connect_ec);
    std::array<std::byte, 1> plain{std::byte{proto::eDonkey}};
    auto [write_ec, n] = co_await asio::async_write(raw, asio::buffer(plain), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(write_ec);
    EXPECT_EQ(n, plain.size());
    boost::system::error_code ignored;
    raw.close(ignored);
    asio::steady_timer timer(rt.context());
    timer.expires_after(20ms);
    co_await timer.async_wait(asio::use_awaitable);
    co_return;
  });
  EXPECT_TRUE(checked);
}

TEST(EncryptedStreamSocket, AcceptorRejectsEncryptedWrongMagic) {
  IoRuntime rt;
  bool checked = false;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void> {
    EncryptedStreamSocket socket(std::move(s));
    auto handshake = co_await socket.handshake_acceptor(user_hash(), 2s, deterministic_options());
    EXPECT_FALSE(handshake.has_value());
    if (!handshake) {
      EXPECT_EQ(handshake.error(), make_error_code(errc::bad_magic));
    }
    checked = true;
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    tcp::socket raw(rt.context());
    auto [connect_ec] = co_await raw.async_connect(
        tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()),
        asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(connect_ec);
    auto request = encrypted_bad_magic_request(user_hash());
    auto [write_ec, n] = co_await asio::async_write(raw, asio::buffer(request), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(write_ec);
    EXPECT_EQ(n, request.size());
    boost::system::error_code ignored;
    raw.close(ignored);
    asio::steady_timer timer(rt.context());
    timer.expires_after(20ms);
    co_await timer.async_wait(asio::use_awaitable);
    co_return;
  });
  EXPECT_TRUE(checked);
}

TEST(EncryptedStreamSocket, HandshakeEncryptsFrameRoundTrip) {
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void> {
    EncryptedStreamSocket socket(std::move(s));
    auto handshake = co_await socket.handshake_acceptor(user_hash(), 2s, deterministic_options());
    EXPECT_TRUE(handshake.has_value());
    if (!handshake) {
      co_return;
    }
    auto packet = co_await socket.recv(2s);
    EXPECT_TRUE(packet.has_value());
    if (!packet) {
      co_return;
    }
    EXPECT_EQ(packet->protocol, proto::eMule);
    EXPECT_EQ(packet->opcode, 0x51);
    EXPECT_EQ(packet->payload, std::vector<std::byte>({std::byte{0x10}, std::byte{0x20}}));

    Packet reply;
    reply.protocol = proto::eDonkey;
    reply.opcode = 0x52;
    reply.payload = {std::byte{0x30}};
    auto sent = co_await socket.send(reply);
    EXPECT_TRUE(sent.has_value());
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    EncryptedStreamSocket socket(rt.executor());
    auto connected = co_await socket.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(connected.has_value());
    if (!connected) {
      co_return;
    }
    auto handshake = co_await socket.handshake_initiator(user_hash(), 2s, deterministic_options());
    EXPECT_TRUE(handshake.has_value());
    if (!handshake) {
      co_return;
    }
    Packet request;
    request.protocol = proto::eMule;
    request.opcode = 0x51;
    request.payload = {std::byte{0x10}, std::byte{0x20}};
    auto sent = co_await socket.send(request);
    EXPECT_TRUE(sent.has_value());
    auto reply = co_await socket.recv(2s);
    EXPECT_TRUE(reply.has_value());
    if (reply) {
      EXPECT_EQ(reply->protocol, proto::eDonkey);
      EXPECT_EQ(reply->opcode, 0x52);
      EXPECT_EQ(reply->payload, std::vector<std::byte>({std::byte{0x30}}));
    }
    socket.close();
    co_return;
  });
}

TEST(EncryptedStreamSocket, Rc4StateContinuesAcrossMultipleFramesInBothDirections) {
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void> {
    EncryptedStreamSocket socket(std::move(s));
    auto handshake = co_await socket.handshake_acceptor(user_hash(), 2s, deterministic_options());
    EXPECT_TRUE(handshake.has_value());
    if (!handshake) {
      co_return;
    }
    auto first = co_await socket.recv(2s);
    auto second = co_await socket.recv(2s);
    EXPECT_TRUE(first.has_value());
    EXPECT_TRUE(second.has_value());
    if (first) {
      EXPECT_EQ(first->opcode, 0x61);
      EXPECT_EQ(first->payload, std::vector<std::byte>({std::byte{0x01}}));
    }
    if (second) {
      EXPECT_EQ(second->opcode, 0x62);
      EXPECT_EQ(second->payload, std::vector<std::byte>({std::byte{0x02}, std::byte{0x03}, std::byte{0x04}}));
    }

    Packet a;
    a.protocol = proto::eMule;
    a.opcode = 0x71;
    a.payload = {std::byte{0x0a}};
    Packet b;
    b.protocol = proto::eMule;
    b.opcode = 0x72;
    b.payload = {std::byte{0x0b}, std::byte{0x0c}};
    EXPECT_TRUE((co_await socket.send(a)).has_value());
    EXPECT_TRUE((co_await socket.send(b)).has_value());
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    EncryptedStreamSocket socket(rt.executor());
    auto connected = co_await socket.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(connected.has_value());
    if (!connected) {
      co_return;
    }
    auto handshake = co_await socket.handshake_initiator(user_hash(), 2s, deterministic_options());
    EXPECT_TRUE(handshake.has_value());
    if (!handshake) {
      co_return;
    }
    Packet first;
    first.protocol = proto::eDonkey;
    first.opcode = 0x61;
    first.payload = {std::byte{0x01}};
    Packet second;
    second.protocol = proto::eDonkey;
    second.opcode = 0x62;
    second.payload = {std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
    EXPECT_TRUE((co_await socket.send(first)).has_value());
    EXPECT_TRUE((co_await socket.send(second)).has_value());

    auto a = co_await socket.recv(2s);
    auto b = co_await socket.recv(2s);
    EXPECT_TRUE(a.has_value());
    EXPECT_TRUE(b.has_value());
    if (a) {
      EXPECT_EQ(a->opcode, 0x71);
      EXPECT_EQ(a->payload, std::vector<std::byte>({std::byte{0x0a}}));
    }
    if (b) {
      EXPECT_EQ(b->opcode, 0x72);
      EXPECT_EQ(b->payload, std::vector<std::byte>({std::byte{0x0b}, std::byte{0x0c}}));
    }
    socket.close();
    co_return;
  });
}
