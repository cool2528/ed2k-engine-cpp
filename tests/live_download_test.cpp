#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <boost/asio/co_spawn.hpp>
#include "ed2k/app/server_session.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include "live_env.hpp"
using namespace ed2k; using namespace ed2k::app;
namespace asio = boost::asio;
using namespace std::chrono_literals;
template <class F> static void run_coro(ed2k::net::IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}
TEST(LiveDownload, HighIdSourceCompletes){
  if(!ed2k::test::live_enabled()) GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_LINK=... ED2K_EXPECT_MD4=...";
  auto ls = ed2k::test::env_link(); if(ls.empty()) GTEST_SKIP() << "set ED2K_LINK";
  auto pl = parse_link(ls); ASSERT_TRUE(pl.has_value());
  auto* f = std::get_if<Ed2kFileLink>(&*pl); ASSERT_NE(f, nullptr);
  auto out = std::filesystem::temp_directory_path() / "ed2k_live_dl";
  std::filesystem::remove(out);
  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    DownloadOpts o; o.out_path=out; o.total_timeout=std::chrono::seconds(300);
    auto r = co_await download_link(rt.executor(), *f, {}, ed2k::test::env_server(), o);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    co_return;
  });
  if(!std::filesystem::exists(out)) GTEST_SKIP() << "download did not complete";
  EXPECT_EQ(std::filesystem::file_size(out), f->size);
  auto exp = ed2k::test::env_expect_md4();
  if(!exp.empty()){
    auto h = hash_file(out.string(), HashVariant::Red);   // aMule/eMule Red 变体 (空尾 part)
    EXPECT_TRUE(h.has_value());
    if(h) EXPECT_EQ(h->file_hash.to_hex(), exp);
  }
  std::filesystem::remove(out);
}
// Direct-connect download against a real, independent eMule implementation
// (aMule 2.3.3 daemon run locally in WSL2). Validates the full P2P download
// path — HELLO/HELLOANSWER, SETREQFILEID/FILESTATUS, HASHSETREQUEST/ANSWER,
// REQUESTFILENAME/ANSWER, STARTUPLOADREQ/ACCEPTUPLOADREQ/QUEUERANKING,
// REQUESTPARTS/SENDINGPART, MD4 verify — against a reference peer, bypassing
// the public eMule network (whose sources IP-filter our cloud IP, see §6 R0-1).
// Env: ED2K_LIVE=1 ED2K_LINK=ed2k://|file|...|size|hash|/ ED2K_SOURCE=ip:port
//      ED2K_EXPECT_MD4=<hex>  (ED2K_SOURCE = the local aMule peer, HighID)
TEST(LiveDownload, LocalPeerCompletes){
  if(!ed2k::test::live_enabled()) GTEST_SKIP();
  auto ls = ed2k::test::env_link(); if(ls.empty()) GTEST_SKIP() << "set ED2K_LINK";
  const char* src_s = std::getenv("ED2K_SOURCE");
  if(!src_s || !*src_s) GTEST_SKIP() << "set ED2K_SOURCE=ip:port";
  std::string ss(src_s);
  auto colon = ss.rfind(':');
  ASSERT_NE(colon, std::string::npos) << "ED2K_SOURCE must be ip:port";
  auto ip = IPv4::from_dotted(ss.substr(0, colon));
  ASSERT_TRUE(ip.has_value()) << "bad ED2K_SOURCE ip";
  std::uint16_t port = std::uint16_t(std::stoi(ss.substr(colon + 1)));
  // IPv4.value is a-high-byte (asio order); SourceEndpoint.id is aMule-LE
  // (a-low-byte) so that low_id() detection + IPv4::from_wire(id) bswap work.
  std::uint32_t id = ((ip->value & 0x000000FFu) << 24) |
                     ((ip->value & 0x0000FF00u) << 8)  |
                     ((ip->value & 0x00FF0000u) >> 8)  |
                     ((ip->value & 0xFF000000u) >> 24);
  ed2k::server::SourceEndpoint src{ id, port };
  ASSERT_FALSE(src.low_id()) << "ED2K_SOURCE must be a HighID (reachable) peer";

  auto pl = parse_link(ls); ASSERT_TRUE(pl.has_value());
  auto* f = std::get_if<Ed2kFileLink>(&*pl); ASSERT_NE(f, nullptr);
  auto out = std::filesystem::temp_directory_path() / "ed2k_live_local_dl";
  std::filesystem::remove(out);
  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ed2k::download::MultiSourceDownload dl(rt.executor(), out, f->hash, f->size,
                                           std::nullopt, std::vector{src},
                                           nullptr, nullptr);
    auto r = co_await dl.run(std::chrono::seconds(300), 3);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });
  ASSERT_TRUE(std::filesystem::exists(out)) << "download did not complete";
  EXPECT_EQ(std::filesystem::file_size(out), f->size);
  auto exp = ed2k::test::env_expect_md4();
  if(!exp.empty()){
    auto h = hash_file(out.string(), HashVariant::Red);   // aMule/eMule Red 变体 (空尾 part)
    ASSERT_TRUE(h.has_value());
    EXPECT_EQ(h->file_hash.to_hex(), exp);
  }
  std::filesystem::remove(out);
}
