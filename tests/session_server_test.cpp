#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/app/server_session.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/server/opcodes.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/session/session.hpp"
#include "ed2k/util/error.hpp"
#include "mock_server.hpp"
using namespace ed2k; using namespace ed2k::net;
using ed2k::session::Session;
using ed2k::session::SessionConfig;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}
static asio::awaitable<void> send_pkt(tcp::socket& s, std::uint8_t op, std::span<const std::byte> pl){
  Packet p; p.protocol=proto::eDonkey; p.opcode=op; p.payload.assign(pl.begin(),pl.end());
  auto fr=encode_frame(p); auto [e,n]=co_await asio::async_write(s,asio::buffer(fr),asio::as_tuple(asio::use_awaitable)); (void)e;(void)n; co_return;
}
static asio::awaitable<std::vector<std::byte>> read_frame(tcp::socket& s){
  std::array<std::byte,5> hdr; auto [e1,n1]=co_await asio::async_read(s,asio::buffer(hdr),asio::as_tuple(asio::use_awaitable)); (void)n1;
  if(e1) co_return std::vector<std::byte>{};
  auto h=parse_header(hdr); if(!h) co_return std::vector<std::byte>{};
  std::vector<std::byte> body(h->size); auto [e2,n2]=co_await asio::async_read(s,asio::buffer(body),asio::as_tuple(asio::use_awaitable)); (void)n2;
  if(e2) co_return std::vector<std::byte>{};
  co_return body;
}
static asio::awaitable<void> keep_alive(tcp::socket& s){ std::array<std::byte,1> t; auto [e,n]=co_await asio::async_read(s,asio::buffer(t),asio::as_tuple(asio::use_awaitable)); (void)e;(void)n; co_return; }

TEST(SessionServer, ConnectEmitsStateAndDisconnectClears){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    co_await keep_alive(s);
    co_return;
  });
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_srv_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg; cfg.data_dir = tmp_dir; cfg.per_server_timeout = 3000ms;
  Session session(rt, cfg);
  std::vector<ed2k::session::ServerStateEvent> events;
  session.set_event_handler([&](const ed2k::session::SessionEvent& ev){
    if(auto* e = std::get_if<ed2k::session::ServerStateEvent>(&ev)) events.push_back(*e);
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await session.connect_server(
      ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()});
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;                     // 协程体内禁用 ASSERT_*; 失败时守卫式提前返回
    EXPECT_TRUE(r->high_id);
    EXPECT_TRUE(session.server_connected());
    session.disconnect_server();
    EXPECT_FALSE(session.server_connected());
    co_return;
  });
  ASSERT_GE(events.size(), 2u);
  EXPECT_TRUE(events.front().connected);
  EXPECT_FALSE(events.back().connected);
  std::filesystem::remove_all(tmp_dir);
}

TEST(SessionServer, AddRemovePersistsServerMet){
  IoRuntime rt;
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_met_test";
  std::filesystem::remove_all(tmp_dir);
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg; cfg.data_dir = tmp_dir;
  {
    Session session(rt, cfg);
    EXPECT_TRUE(session.add_server(IPv4::from_dotted("10.0.0.1").value(), 4661, "alpha"));
    EXPECT_FALSE(session.add_server(IPv4::from_dotted("10.0.0.1").value(), 4661, "alpha"));  // 去重
    EXPECT_EQ(session.server_list().size(), 1u);
  }
  {
    Session session2(rt, cfg);                       // 重新加载 server.met
    auto list = session2.server_list();
    ASSERT_EQ(list.size(), 1u);
    EXPECT_EQ(list[0].port, 4661);
    EXPECT_TRUE(session2.remove_server(list[0].ip, list[0].port));
    EXPECT_TRUE(session2.server_list().empty());
  }
  std::filesystem::remove_all(tmp_dir);
}
