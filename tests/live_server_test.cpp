#include <gtest/gtest.h>
#include <chrono>
#include <boost/asio/co_spawn.hpp>
#include "ed2k/app/server_session.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/server/connection.hpp"
#include "ed2k/server/search_query.hpp"
#include "ed2k/server/udp_connection.hpp"
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

static asio::awaitable<tl::expected<LoginSession, std::error_code>>
login_live_server(asio::any_io_executor ex){
  const auto target = ed2k::test::env_server();
  const char* explicit_endpoint = std::getenv("ED2K_SERVER");
  if(explicit_endpoint && *explicit_endpoint && !target) {
    co_return tl::unexpected(std::make_error_code(std::errc::invalid_argument));
  }
  if(!target) {
    co_return co_await login_with_rotation(ex, {}, std::nullopt, default_login(), 15000ms);
  }
  ServerConnection conn(ex);
  auto result = co_await conn.connect_and_login(target->ip, target->port, default_login(), 15000ms);
  if(!result) co_return tl::unexpected(result.error());
  co_return LoginSession{std::move(conn), *result};
}

TEST(LiveServer, LoginReturnsId){
  if(!ed2k::test::live_enabled()) GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_SERVER=ip:port";
  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await login_live_server(rt.executor());
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
    auto lg = co_await login_live_server(rt.executor());
    EXPECT_TRUE(lg.has_value()); if(!lg) co_return;
    const auto term = ed2k::test::env_search_term();
    std::printf("  search_term=%s\n", term.c_str());
    auto sr = co_await lg->conn.search(Keyword{term}, 15000ms);
    EXPECT_TRUE(sr.has_value()) << (sr? "" : sr.error().message());
    if(!sr) co_return;
    EXPECT_FALSE(sr->empty());
    co_return;
  });
}
TEST(LiveServer, GetSourcesReturnsOk){
  if(!ed2k::test::live_enabled()) GTEST_SKIP();
  FileHash hash = *FileHash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0");
  std::uint64_t size = 1;
  const auto link_s = ed2k::test::env_link();
  if(!link_s.empty()) {
    auto pl = parse_link(link_s);
    ASSERT_TRUE(pl.has_value());
    auto* f = std::get_if<Ed2kFileLink>(&*pl);
    ASSERT_NE(f, nullptr);
    hash = f->hash;
    size = f->size;
  }
  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto lg = co_await login_live_server(rt.executor());
    EXPECT_TRUE(lg.has_value()); if(!lg) co_return;
    auto gs = co_await lg->conn.get_sources(hash, size, 15000ms);
    EXPECT_TRUE(gs.has_value()) << (gs? "" : gs.error().message());
    if(!gs) co_return;
    // 源列表可为空(调用成功即过); 非空则 endpoint port 合法
    for(const auto& s : gs->sources) EXPECT_NE(s.port, 0u);
    co_return;
  });
}

TEST(LiveServer, UdpObfuscationProbe){
  if(!ed2k::test::live_enabled()) GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_SERVER=ip:port";
  const auto target = ed2k::test::env_server();
  ASSERT_TRUE(target.has_value()) << "UDP capability probe requires an explicit ED2K_SERVER endpoint";
  ASSERT_LE(target->port, 65531u) << "selected TCP port cannot map to the conventional UDP port";

  ed2k::net::IoRuntime rt;
  std::string capability_unavailable;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    constexpr std::uint32_t stat_challenge = 0x55AA4C49u;
    constexpr std::uint32_t encrypted_stat_challenge = 0x55AA4C4Au;
    constexpr std::uint32_t desc_challenge = 0x4F42F0FFu;
    const auto plain_udp_port = static_cast<std::uint16_t>(target->port + 4);
    UdpServerConnection plain(rt.executor(), target->ip, plain_udp_port);
    auto stat = co_await plain.server_status(stat_challenge, 5000ms);
    if(!stat) {
      capability_unavailable = "plain status exchange failed: " + stat.error().message();
      co_return;
    }
    auto desc = co_await plain.server_desc(desc_challenge, 5000ms);
    if(!desc) {
      capability_unavailable = "plain description exchange failed: " + desc.error().message();
      co_return;
    }
    plain.close();
    if(stat->udp_key == 0 || stat->udp_obf_port == 0) {
      capability_unavailable = "server did not advertise a fresh key and port";
      co_return;
    }

    std::printf("  udp_server=%s:%u obfuscated_port=%u name=%s\n",
                target->ip.to_dotted().c_str(), plain_udp_port, stat->udp_obf_port,
                desc->name.c_str());
    UdpServerConnection encrypted(
        rt.executor(), target->ip, plain_udp_port,
        UdpServerObfuscation{
            .udp_key = stat->udp_key,
            .udp_port = stat->udp_obf_port,
            .probe_timeout = 5000ms,
            .fallback_plain = false,
        });
    auto encrypted_stat = co_await encrypted.server_status(encrypted_stat_challenge, 5000ms);
    EXPECT_TRUE(encrypted_stat.has_value())
        << "server advertised UDP obfuscation metadata but encrypted probe failed: "
        << (encrypted_stat ? "" : encrypted_stat.error().message());
    if(!encrypted_stat) co_return;
    EXPECT_TRUE(encrypted.last_response_encrypted())
        << "probe response was not encrypted";
    encrypted.close();
    co_return;
  });
  if(!capability_unavailable.empty()) {
    GTEST_SKIP() << "UDP obfuscation capability unavailable: " << capability_unavailable;
  }
}
