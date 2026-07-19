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
#include <boost/asio/steady_timer.hpp>
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

// 回归(C1): eD2k 不是心跳协议, 服务器登录后长时间静默(仅登录时发一次 STATUS/IDENT)是正常现象。
// mock server 发完 IDCHANGE 后只保持连接打开、不再推送/不关闭; per_server_timeout 设得很短
// (300ms), 等待跨越好几个超时窗口后, 连接必须仍然存活, 且不应该收到任何 disconnected 事件
// (期间 receive_events 的 timed_out 不能被误判为断线)。
TEST(SessionServer, StaysConnectedThroughIdleTimeout){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    co_await keep_alive(s);         // 保持连接打开、不再推送、不关闭
    co_return;
  });
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_srv_idle_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg; cfg.data_dir = tmp_dir; cfg.per_server_timeout = 300ms;
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
    EXPECT_TRUE(session.server_connected());
    // 跨越约 3 个 per_server_timeout 周期静默等待(模拟真实服务器长时间不推送)
    asio::steady_timer timer(rt.context());
    timer.expires_after(cfg.per_server_timeout * 3);
    co_await timer.async_wait(asio::use_awaitable);
    EXPECT_TRUE(session.server_connected());   // 修复前: receive_loop 会把首次 timed_out 误判为断线
    session.disconnect_server();
    co_return;
  });
  // 期望恰好两条事件: connect 时的 connected=true, 以及测试末尾主动 disconnect 的 connected=false。
  // 中途若混入任何 timed_out 触发的伪断线事件, 数量会大于 2。
  ASSERT_EQ(events.size(), 2u);
  EXPECT_TRUE(events.front().connected);
  EXPECT_FALSE(events.back().connected);
  std::filesystem::remove_all(tmp_dir);
}

// 回归(C2): connect_server 收到的 ServerIdentEvent 除 name 外还带着服务器自报的 ip/port——
// login_with_rotation 可能故障转移到 target 之外的服务器, 因此最终 server_state 的 ip/port
// 必须以 ServerIdentEvent 的值为准, 而不是停留在最初连接请求的 target 占位值上。
TEST(SessionServer, IdentUpdatesServerAddress){
  IoRuntime rt;
  const auto ident_ip = IPv4::from_dotted("203.0.113.7").value();   // 刻意不同于 target(127.0.0.1)
  const std::uint16_t ident_port = 5555;                            // 刻意不同于 target 的 srv.port()
  const std::string ident_name = "real-server";
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    { codec::ByteWriter w;
      w.hash16(MD4Hash{});
      w.u32_be(ident_ip.host());
      w.u16(ident_port);
      codec::Tag name_tag; name_tag.name_id = ed2k::server::tag::ST_SERVERNAME; name_tag.value = ident_name;
      std::vector<codec::Tag> tags{name_tag};
      w.u32(static_cast<std::uint32_t>(tags.size()));
      codec::write_taglist(w, tags);
      co_await send_pkt(s, ed2k::server::op::SERVERIDENT, w.take());
    }
    co_await keep_alive(s);
    co_return;
  });
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_srv_ident_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg; cfg.data_dir = tmp_dir; cfg.per_server_timeout = 3000ms;
  Session session(rt, cfg);
  std::vector<ed2k::session::ServerStateEvent> events;
  session.set_event_handler([&](const ed2k::session::SessionEvent& ev){
    if(auto* e = std::get_if<ed2k::session::ServerStateEvent>(&ev)) events.push_back(*e);
  });
  const auto target_ip = IPv4::from_dotted("127.0.0.1").value();
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await session.connect_server(ed2k::app::ServerTarget{target_ip, srv.port()});
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;                     // 协程体内禁用 ASSERT_*; 失败时守卫式提前返回
    // 让 receive_loop 有机会跑一轮, 收下 mock server 推送的 SERVERIDENT 并分发。
    asio::steady_timer timer(rt.context());
    timer.expires_after(200ms);
    co_await timer.async_wait(asio::use_awaitable);
    co_return;
  });
  ASSERT_EQ(events.size(), 2u);           // connect 时的初始占位事件 + ident 更新后的事件
  EXPECT_TRUE(events.front().connected);
  EXPECT_EQ(events.front().ip, target_ip);          // 初始事件仍是占位的 target 地址
  const auto& last = events.back();
  EXPECT_TRUE(last.connected);
  EXPECT_EQ(last.ip, ident_ip);            // 修复前: 停留在 target_ip, 不会被 ident 覆盖
  EXPECT_EQ(last.port, ident_port);
  EXPECT_EQ(last.name, ident_name);
  std::filesystem::remove_all(tmp_dir);
}
