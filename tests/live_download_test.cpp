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
    auto h = hash_file(out.string(), HashVariant::Blue);
    EXPECT_TRUE(h.has_value());
    if(h) EXPECT_EQ(h->file_hash.to_hex(), exp);
  }
  std::filesystem::remove(out);
}
