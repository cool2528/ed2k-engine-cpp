#include <gtest/gtest.h>
#include <chrono>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/encrypted_stream_socket.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/util/error.hpp"
using namespace ed2k; using namespace ed2k::peer;
namespace asio = boost::asio; using tcp = asio::ip::tcp;
using namespace std::chrono_literals;
template <class F> static void run_coro(ed2k::net::IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}
TEST(InboundListener, AcceptsInboundConnection){
  ed2k::net::IoRuntime rt;
  InboundListener lst(rt.executor(), 0);   // ephemeral port
  EXPECT_NE(lst.local_port(), 0u);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    // 同时发起 accept 与一个出站连接
    tcp::socket client(rt.executor());
    tcp::endpoint ep(asio::ip::make_address_v4("127.0.0.1"), lst.local_port());
    auto [ec] = co_await client.async_connect(ep, asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec);
    auto acc = co_await lst.accept(2000ms);
    EXPECT_TRUE(acc.has_value()) << (acc? "" : acc.error().message());
    if(!acc) co_return;
    EXPECT_TRUE(acc->is_open());
    // 回声验证: client 写一字节, accept 侧读到
    std::byte out{0xAB};
    auto [we,wn] = co_await asio::async_write(client, asio::buffer(&out,1), asio::as_tuple(asio::use_awaitable));(void)we;(void)wn;
    std::byte in{};
    auto [re,rn] = co_await asio::async_read(*acc, asio::buffer(&in,1), asio::as_tuple(asio::use_awaitable));(void)re;(void)rn;
    EXPECT_EQ(in, std::byte(0xAB));
    co_return;
  });
}
TEST(InboundListener, AcceptTimesOut){
  ed2k::net::IoRuntime rt;
  InboundListener lst(rt.executor(), 0);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto acc = co_await lst.accept(200ms);
    EXPECT_FALSE(acc.has_value());
    if(!acc) EXPECT_EQ(acc.error(), make_error_code(errc::timed_out));
    co_return;
  });
}

static UserHash listener_hash() {
  return *UserHash::from_hex("0123456789abcdeffedcba9876543210");
}
static HelloInfo listener_hello(std::string nickname) {
  HelloInfo hello;
  hello.nickname = std::move(nickname);
  hello.version = 0x3c;
  hello.port = 4662;
  hello.user_hash = listener_hash();
  return hello;
}

TEST(InboundListener, RequiredObfuscationRejectsPlainMarker) {
  ed2k::net::IoRuntime rt;
  InboundListener listener(rt.executor(), 0);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    tcp::socket client(rt.executor());
    co_await client.async_connect(
        tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), listener.local_port()),
        asio::use_awaitable);
    const std::byte marker{ed2k::net::proto::eDonkey};
    co_await asio::async_write(client, asio::buffer(&marker, 1), asio::use_awaitable);
    auto accepted = co_await listener.accept_peer(
        listener_hash(), ObfuscationPolicy::required, 500ms);
    EXPECT_FALSE(accepted.has_value());
    co_return;
  });
}

TEST(InboundListener, RejectsFilteredPeerBeforeReadingMarker) {
  ed2k::net::IoRuntime rt;
  InboundListener listener(rt.executor(), 0);
  auto filter = std::make_shared<ed2k::infra::IPFilter>();
  filter->add(ed2k::infra::IPRange{
      .start = *IPv4::from_dotted("127.0.0.1"),
      .end = *IPv4::from_dotted("127.0.0.1"),
      .level = 200,
      .name = "loopback",
  });
  run_coro(rt, [&]() -> asio::awaitable<void> {
    tcp::socket client(rt.executor());
    co_await client.async_connect(
        tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), listener.local_port()),
        asio::use_awaitable);
    auto accepted = co_await listener.accept_peer(
        listener_hash(), ObfuscationPolicy::preferred, 500ms, filter, 127);
    EXPECT_FALSE(accepted.has_value());
    if (!accepted) EXPECT_EQ(accepted.error(), make_error_code(errc::ip_filtered));
    co_return;
  });
}

TEST(InboundListener, PreferredObfuscationAcceptsPlainAndPreservesMarker) {
  ed2k::net::IoRuntime rt;
  InboundListener listener(rt.executor(), 0);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    tcp::socket client(rt.executor());
    co_await client.async_connect(
        tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), listener.local_port()),
        asio::use_awaitable);
    ed2k::net::Packet hello_packet;
    hello_packet.protocol = ed2k::net::proto::eDonkey;
    hello_packet.opcode = op::HELLO;
    hello_packet.payload = encode_hello_packet(listener_hello("plain-client"));
    auto frame = ed2k::net::encode_frame(hello_packet);
    co_await asio::async_write(client, asio::buffer(frame), asio::use_awaitable);

    auto accepted = co_await listener.accept_peer(
        listener_hash(), ObfuscationPolicy::preferred, 500ms);
    EXPECT_TRUE(accepted.has_value()) << (accepted ? "" : accepted.error().message());
    if (!accepted) co_return;
    EXPECT_FALSE(accepted->encrypted());
    auto hello = co_await accepted->handshake_acceptor(listener_hello("server"), 500ms);
    EXPECT_TRUE(hello.has_value()) << (hello ? "" : hello.error().message());
    if (hello) EXPECT_EQ(hello->nickname, "plain-client");
    co_return;
  });
}

TEST(InboundListener, PreferredObfuscationAcceptsEncryptedStream) {
  ed2k::net::IoRuntime rt;
  InboundListener listener(rt.executor(), 0);
  boost::asio::experimental::channel<void(boost::system::error_code, bool)> completed(rt.executor(), 1);
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void> {
    ed2k::net::EncryptedStreamSocket client(rt.executor());
    auto connected = co_await client.connect(*IPv4::from_dotted("127.0.0.1"),
                                             listener.local_port(), 500ms);
    if (!connected) co_return;
    auto negotiated = co_await client.handshake_initiator(listener_hash(), 500ms);
    if (!negotiated) co_return;
    ed2k::net::Packet hello_packet;
    hello_packet.protocol = ed2k::net::proto::eDonkey;
    hello_packet.opcode = op::HELLO;
    hello_packet.payload = encode_hello_packet(listener_hello("encrypted-client"));
    if (!(co_await client.send(hello_packet))) co_return;
    auto answer = co_await client.recv(500ms);
    completed.try_send(boost::system::error_code{}, answer && answer->opcode == op::HELLOANSWER);
    co_return;
  }, asio::detached);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    auto accepted = co_await listener.accept_peer(
        listener_hash(), ObfuscationPolicy::preferred, 500ms);
    EXPECT_TRUE(accepted.has_value()) << (accepted ? "" : accepted.error().message());
    if (!accepted) co_return;
    EXPECT_TRUE(accepted->encrypted());
    auto hello = co_await accepted->handshake_acceptor(listener_hello("server"), 500ms);
    EXPECT_TRUE(hello.has_value()) << (hello ? "" : hello.error().message());
    if (hello) EXPECT_EQ(hello->nickname, "encrypted-client");
    EXPECT_TRUE(co_await completed.async_receive(asio::use_awaitable));
    co_return;
  });
}
