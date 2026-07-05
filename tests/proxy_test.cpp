#include <array>
#include <chrono>
#include <exception>
#include <string>
#include <vector>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <gtest/gtest.h>

#include "ed2k/infra/proxy.hpp"
#include "ed2k/net/connection.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/net/runtime.hpp"
#include "mock_peer.hpp"

using namespace ed2k;
using namespace ed2k::infra;
using namespace ed2k::net;
using namespace std::chrono_literals;

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
      if (e) std::rethrow_exception(e);
    });
  rt.run();
  rt.restart();
  EXPECT_TRUE(done);
}

asio::awaitable<void> wait_for_flag(asio::io_context& ctx, const bool& flag) {
  asio::steady_timer timer(ctx);
  for (int i = 0; i < 20 && !flag; ++i) {
    timer.expires_after(5ms);
    co_await timer.async_wait(asio::use_awaitable);
  }
  co_return;
}
} // namespace

TEST(Proxy, ParsesSocks5AndHttpUris) {
  auto socks = ProxyConfig::parse("socks5://127.0.0.1:1080");
  ASSERT_TRUE(socks.has_value()) << socks.error().message();
  EXPECT_EQ(socks->type, ProxyType::Socks5);
  EXPECT_EQ(socks->host, "127.0.0.1");
  EXPECT_EQ(socks->port, 1080);

  auto http = ProxyConfig::parse("http://proxy.local:8080");
  ASSERT_TRUE(http.has_value()) << http.error().message();
  EXPECT_EQ(http->type, ProxyType::HttpConnect);
  EXPECT_EQ(http->host, "proxy.local");
  EXPECT_EQ(http->port, 8080);
}

TEST(Connection, ConnectViaSocks5ProxySendsTargetRequest) {
  IoRuntime rt;
  ed2k::test::MockPeer proxy(rt.context());
  std::vector<std::byte> greeting;
  std::vector<std::byte> connect_request;
  bool saw_frame = false;

  proxy.serve([&](tcp::socket s) -> asio::awaitable<void> {
    greeting.resize(3);
    auto [g_ec, g_n] = co_await asio::async_read(s, asio::buffer(greeting), asio::as_tuple(asio::use_awaitable));
    if (g_ec) co_return;
    std::array<std::byte, 2> greet_ok{std::byte{0x05}, std::byte{0x00}};
    co_await asio::async_write(s, asio::buffer(greet_ok), asio::as_tuple(asio::use_awaitable));

    connect_request.resize(10);
    auto [c_ec, c_n] = co_await asio::async_read(s, asio::buffer(connect_request), asio::as_tuple(asio::use_awaitable));
    if (c_ec) co_return;
    std::array<std::byte, 10> connect_ok{
      std::byte{0x05}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
      std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
      std::byte{0x00}, std::byte{0x00}};
    co_await asio::async_write(s, asio::buffer(connect_ok), asio::as_tuple(asio::use_awaitable));

    std::array<std::byte, 5> hdr;
    auto [h_ec, h_n] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
    if (!h_ec) saw_frame = parse_header(hdr).has_value();
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    Connection c(rt.executor());
    ProxyConfig config{ProxyType::Socks5, "127.0.0.1", proxy.port()};
    auto cr = co_await c.connect_via_proxy(config, *IPv4::from_dotted("1.2.3.4"), 4662, 2s);
    EXPECT_TRUE(cr.has_value()) << (cr ? "" : cr.error().message());
    if (cr) {
      Packet pkt{proto::eDonkey, 0x4E, {}};
      auto sent = co_await c.send(pkt);
      EXPECT_TRUE(sent.has_value()) << (sent ? "" : sent.error().message());
      co_await wait_for_flag(rt.context(), saw_frame);
    }
    c.close();
    co_return;
  });

  EXPECT_EQ(greeting, (std::vector<std::byte>{std::byte{0x05}, std::byte{0x01}, std::byte{0x00}}));
  ASSERT_EQ(connect_request.size(), 10u);
  EXPECT_EQ(connect_request[0], std::byte{0x05});
  EXPECT_EQ(connect_request[1], std::byte{0x01});
  EXPECT_EQ(connect_request[3], std::byte{0x01});
  EXPECT_EQ(connect_request[4], std::byte{0x01});
  EXPECT_EQ(connect_request[5], std::byte{0x02});
  EXPECT_EQ(connect_request[6], std::byte{0x03});
  EXPECT_EQ(connect_request[7], std::byte{0x04});
  EXPECT_TRUE(saw_frame);
}

TEST(Connection, ConnectViaHttpProxySendsConnectRequest) {
  IoRuntime rt;
  ed2k::test::MockPeer proxy(rt.context());
  std::string request;
  bool saw_frame = false;

  proxy.serve([&](tcp::socket s) -> asio::awaitable<void> {
    asio::streambuf buf;
    auto [r_ec, r_n] = co_await asio::async_read_until(s, buf, "\r\n\r\n", asio::as_tuple(asio::use_awaitable));
    if (r_ec) co_return;
    request.assign(asio::buffers_begin(buf.data()), asio::buffers_end(buf.data()));
    const std::string ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
    co_await asio::async_write(s, asio::buffer(ok), asio::as_tuple(asio::use_awaitable));

    std::array<std::byte, 5> hdr;
    auto [h_ec, h_n] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
    if (!h_ec) saw_frame = parse_header(hdr).has_value();
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    Connection c(rt.executor());
    ProxyConfig config{ProxyType::HttpConnect, "127.0.0.1", proxy.port()};
    auto cr = co_await c.connect_via_proxy(config, *IPv4::from_dotted("1.2.3.4"), 4662, 2s);
    EXPECT_TRUE(cr.has_value()) << (cr ? "" : cr.error().message());
    if (cr) {
      Packet pkt{proto::eDonkey, 0x4E, {}};
      auto sent = co_await c.send(pkt);
      EXPECT_TRUE(sent.has_value()) << (sent ? "" : sent.error().message());
      co_await wait_for_flag(rt.context(), saw_frame);
    }
    c.close();
    co_return;
  });

  EXPECT_NE(request.find("CONNECT 1.2.3.4:4662 HTTP/1.1"), std::string::npos);
  EXPECT_NE(request.find("Host: 1.2.3.4:4662"), std::string::npos);
  EXPECT_TRUE(saw_frame);
}
