#include <gtest/gtest.h>
#include <array>
#include <chrono>
#include <exception>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/server/connection.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/server/search_query.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"
#include "mock_server.hpp"
using namespace ed2k; using namespace ed2k::server; using namespace ed2k::net;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(),
    [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart();
  EXPECT_TRUE(done);
}
static asio::awaitable<std::vector<std::byte>> read_frame(tcp::socket& s){
  std::array<std::byte,5> hdr;
  auto [e1,n1] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
  (void)n1; if(e1) co_return std::vector<std::byte>{};
  auto h = parse_header(hdr);
  if(!h) co_return std::vector<std::byte>{};
  std::vector<std::byte> body(h->size);
  auto [e2,n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
  (void)n2; if(e2) co_return std::vector<std::byte>{};
  co_return body;
}
static asio::awaitable<void> keep_alive(tcp::socket& s){
  std::array<std::byte,1> t;
  auto [e,n] = co_await asio::async_read(s, asio::buffer(t), asio::as_tuple(asio::use_awaitable));
  (void)e;(void)n; co_return;
}
static std::vector<std::byte> msg_payload(std::string_view s){ codec::ByteWriter w; w.string16(s); return w.take(); }
static std::vector<std::byte> status_payload(std::uint32_t u, std::uint32_t f){ codec::ByteWriter w; w.u32(u); w.u32(f); return w.take(); }
static std::vector<std::byte> idchange_payload(std::uint32_t id, std::uint32_t flags){ codec::ByteWriter w; w.u32(id); w.u32(flags); return w.take(); }
static std::vector<std::byte> cb_payload(std::uint32_t ip, std::uint16_t port){ codec::ByteWriter w; w.u32(ip); w.u16(port); return w.take(); }

TEST(ServerConnection, LoginHighId){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::SERVERMESSAGE, msg_payload("Welcome"));
    co_await ed2k::test::send_packet(s, op::SERVERSTATUS, status_payload(100, 5000));
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    std::vector<ServerEvent> evs;
    c.on_event([&](const ServerEvent& e){ evs.push_back(e); });
    LoginParams p; p.nickname="u"; p.client_port=4662;
    p.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
    auto r = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_TRUE(r->high_id);
    EXPECT_EQ(r->client_id, 0x01000000u);
    EXPECT_GE(evs.size(), 2u);
    c.close(); co_return;
  });
}
TEST(ServerConnection, LoginLowId){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(5u, 0u));
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    LoginParams p; p.nickname="u";
    auto r = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_FALSE(r->high_id);
    c.close(); co_return;
  });
}
TEST(ServerConnection, LoginEmitsMessageAndStatus){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::SERVERMESSAGE, msg_payload("Hi"));
    co_await ed2k::test::send_packet(s, op::SERVERSTATUS, status_payload(7, 8));
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0u));
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    std::vector<ServerEvent> evs;
    c.on_event([&](const ServerEvent& e){ evs.push_back(e); });
    LoginParams p; p.nickname="u";
    auto r = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    bool got_msg=false, got_status=false;
    for(auto& e:evs){
      if(std::holds_alternative<ServerMessageEvent>(e)) got_msg = (std::get<ServerMessageEvent>(e).text=="Hi");
      if(std::holds_alternative<ServerStatusEvent>(e)){ auto& st=std::get<ServerStatusEvent>(e); got_status = (st.users==7 && st.files==8); }
    }
    EXPECT_TRUE(got_msg);
    EXPECT_TRUE(got_status);
    c.close(); co_return;
  });
}
TEST(ServerConnection, LoginRejected){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::REJECT);
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    LoginParams p; p.nickname="u";
    auto r = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::login_rejected));
    c.close(); co_return;
  });
}
