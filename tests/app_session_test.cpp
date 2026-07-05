#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/app/server_session.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/server/connection.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"
#include "mock_server.hpp"
using namespace ed2k; using namespace ed2k::app; using namespace ed2k::server;
namespace asio = boost::asio; using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

template <class F> static void run_coro(ed2k::net::IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}
static asio::awaitable<void> read_frame(tcp::socket& s){
  std::array<std::byte,5> hdr;
  auto [e,n] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable)); (void)n;
  if(e) co_return;
  auto h = ed2k::net::parse_header(hdr); if(!h) co_return;
  std::vector<std::byte> body(h->size);
  auto [e2,n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable)); (void)n2;(void)e2;
  co_return;
}
static std::vector<std::byte> idchange_payload(std::uint32_t id, std::uint32_t flags){
  ed2k::codec::ByteWriter w; w.u32(id); w.u32(flags); return w.take();
}

TEST(AppServerSession, BuildTargetsOverrideFirst){
  auto v = build_targets({}, ServerTarget{IPv4::from_dotted("127.0.0.1").value(), 5});
  ASSERT_FALSE(v.empty());
  EXPECT_EQ(v.front().port, 5u);
}
TEST(AppServerSession, BuildTargetsParsesMet){
  ServerList sl; ServerEntry a; a.ip=IPv4::from_dotted("10.0.0.1").value(); a.port=1;
  ServerEntry b; b.ip=IPv4::from_dotted("10.0.0.2").value(); b.port=2;
  sl.servers={a,b};
  auto bytes = write_server_met(sl);
  auto v = build_targets(bytes, std::nullopt);
  // 至少含 met 里的两个(后面还跟 fallback)
  EXPECT_GE(v.size(), 2u);
  EXPECT_EQ(v[0].port, 1u);
  EXPECT_EQ(v[1].port, 2u);
}
TEST(AppServerSession, BuildTargetsPreservesServerObfuscationMetadata){
  ServerList sl;
  ServerEntry server;
  server.ip=IPv4::from_dotted("10.0.0.1").value();
  server.port=4661;
  server.udp_flags=0x00000600u;
  server.udp_key=0x11223344u;
  server.udp_key_ip=0x0A000001u;
  server.tcp_obf_port=4665;
  server.udp_obf_port=4675;
  sl.servers={server};

  auto v = build_targets(write_server_met(sl), std::nullopt);
  ASSERT_FALSE(v.empty());
  EXPECT_EQ(v[0].ip, server.ip);
  EXPECT_EQ(v[0].port, server.port);
  EXPECT_EQ(v[0].udp_flags, server.udp_flags);
  EXPECT_EQ(v[0].udp_key, server.udp_key);
  EXPECT_EQ(v[0].udp_key_ip, server.udp_key_ip);
  EXPECT_EQ(v[0].tcp_obf_port, server.tcp_obf_port);
  EXPECT_EQ(v[0].udp_obf_port, server.udp_obf_port);
}
TEST(AppServerSession, LoginSucceedsOnOverride){
  ed2k::net::IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    co_await read_frame(s);   // LOGINREQUEST
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    std::array<std::byte,1> t; auto [e,n]=co_await asio::async_read(s,asio::buffer(t),asio::as_tuple(asio::use_awaitable));(void)e;(void)n;
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await login_with_rotation(rt.executor(), {},
      ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()},
      LoginParams{}, 3000ms);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;
    EXPECT_TRUE(r->result.high_id);
    EXPECT_EQ(r->result.client_id, 0x01000000u);
    co_return;
  });
}
TEST(AppServerSession, LoginRotatesPastDeadServer){
  ed2k::net::IoRuntime rt;
  ed2k::test::MockServer live(rt.context());
  live.serve([](tcp::socket s) -> asio::awaitable<void>{
    co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    std::array<std::byte,1> t; auto [e,n]=co_await asio::async_read(s,asio::buffer(t),asio::as_tuple(asio::use_awaitable));(void)e;(void)n;
    co_return;
  });
  // met: 先一个死端口, 再 live mock
  ServerList sl; ServerEntry dead; dead.ip=IPv4::from_dotted("127.0.0.1").value(); dead.port=1;
  ServerEntry good; good.ip=IPv4::from_dotted("127.0.0.1").value(); good.port=live.port();
  sl.servers={dead,good};
  auto bytes = write_server_met(sl);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await login_with_rotation(rt.executor(), bytes, std::nullopt, LoginParams{}, 2000ms);
    EXPECT_TRUE(r.has_value());
    if(!r) co_return;
    EXPECT_TRUE(r->result.high_id);
    co_return;
  });
}
