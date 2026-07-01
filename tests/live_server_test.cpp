#include <gtest/gtest.h>
#include <chrono>
#include <boost/asio/co_spawn.hpp>
#include "ed2k/app/server_session.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/server/connection.hpp"
#include "ed2k/server/search_query.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "live_env.hpp"
using namespace ed2k; using namespace ed2k::app; using namespace ed2k::server;
namespace asio = boost::asio;
using namespace std::chrono_literals;

static ed2k::server::LoginParams default_login(){
  ed2k::server::LoginParams p;
  p.nickname = "ed2k-tool";
  p.client_port = 4662;
  p.user_hash = *ed2k::UserHash::from_hex("0123456789abcdeffedcba9876543210");
  return p;
}
template <class F> static void run_coro(ed2k::net::IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}

TEST(LiveServer, LoginReturnsId){
  if(!ed2k::test::live_enabled()) GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_SERVER=ip:port";
  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await login_with_rotation(rt.executor(), {}, ed2k::test::env_server(), default_login(), 15000ms);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;
    EXPECT_NE(r->result.client_id, 0u);
    // high_id may be false behind NAT — record but do not assert
    std::printf("  client_id=0x%08X high_id=%d\n", r->result.client_id, r->result.high_id ? 1 : 0);
    co_return;
  });
}
TEST(LiveServer, SearchReturnsResults){
  if(!ed2k::test::live_enabled()) GTEST_SKIP();
  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto lg = co_await login_with_rotation(rt.executor(), {}, ed2k::test::env_server(), default_login(), 15000ms);
    EXPECT_TRUE(lg.has_value()); if(!lg) co_return;
    auto sr = co_await lg->conn.search(Keyword{"emule"}, 15000ms);
    EXPECT_TRUE(sr.has_value()) << (sr? "" : sr.error().message());
    if(!sr) co_return;
    EXPECT_FALSE(sr->empty());
    co_return;
  });
}
TEST(LiveServer, GetSourcesReturnsOk){
  if(!ed2k::test::live_enabled()) GTEST_SKIP();
  auto link_s = ed2k::test::env_link();
  if(link_s.empty()) GTEST_SKIP() << "set ED2K_LINK";
  auto pl = parse_link(link_s);
  ASSERT_TRUE(pl.has_value());
  auto* f = std::get_if<Ed2kFileLink>(&*pl);
  ASSERT_NE(f, nullptr);
  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto lg = co_await login_with_rotation(rt.executor(), {}, ed2k::test::env_server(), default_login(), 15000ms);
    EXPECT_TRUE(lg.has_value()); if(!lg) co_return;
    auto gs = co_await lg->conn.get_sources(f->hash, f->size, 15000ms);
    EXPECT_TRUE(gs.has_value()) << (gs? "" : gs.error().message());
    if(!gs) co_return;
    // 源列表可为空(调用成功即过); 非空则 endpoint port 合法
    for(const auto& s : gs->sources) EXPECT_NE(s.port, 0u);
    co_return;
  });
}
