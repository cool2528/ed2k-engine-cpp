#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <boost/asio/co_spawn.hpp>
#include "ed2k/app/server_session.hpp"
#include "ed2k/download/part_file.hpp"
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
  // IPv4.host() is a-high-byte (asio order); SourceEndpoint.id is aMule-LE
  // (a-low-byte) so that low_id() detection + IPv4::from_wire(id) bswap work.
  std::uint32_t v = ip->host();
  std::uint32_t id = ((v & 0x000000FFu) << 24) |
                     ((v & 0x0000FF00u) << 8)  |
                     ((v & 0x00FF0000u) >> 8)  |
                     ((v & 0xFF000000u) >> 24);
  ed2k::server::SourceEndpoint src{ id, port };
  ASSERT_FALSE(src.low_id()) << "ED2K_SOURCE must be a HighID (reachable) peer";

  auto pl = parse_link(ls); ASSERT_TRUE(pl.has_value());
  auto* f = std::get_if<Ed2kFileLink>(&*pl); ASSERT_NE(f, nullptr);
  const char* out_s = std::getenv("ED2K_OUT");
  const bool preserve_out = out_s && *out_s;
  auto out = preserve_out ? std::filesystem::path(out_s)
                          : (std::filesystem::temp_directory_path() / "ed2k_live_local_dl");
  if(!preserve_out) std::filesystem::remove(out);
  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = ed2k::download::MultiSourceDownload::Builder(rt.executor())
                .out(out)
                .hash(f->hash)
                .size(f->size)
                .aich(std::nullopt)
                .sources(std::vector{src})
                .build();
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
  if(!preserve_out) std::filesystem::remove(out);
}

TEST(LivePartMet, WritesEnginePartialFixture){
  const char* source_s = std::getenv("ED2K_PARTIAL_SOURCE");
  const char* out_s = std::getenv("ED2K_PARTIAL_OUT");
  if(!source_s || !*source_s || !out_s || !*out_s) {
    GTEST_SKIP() << "set ED2K_PARTIAL_SOURCE and ED2K_PARTIAL_OUT";
  }

  const std::filesystem::path source = source_s;
  const std::filesystem::path out = out_s;
  ASSERT_TRUE(std::filesystem::exists(source));
  std::filesystem::create_directories(out.parent_path());
  std::filesystem::remove(out);
  auto met = out;
  met += (out.extension() == ".part") ? ".met" : ".part.met";
  std::filesystem::remove(met);

  auto h = hash_file(source.string(), HashVariant::Red);
  ASSERT_TRUE(h.has_value()) << h.error().message();
  const auto size = std::filesystem::file_size(source);
  ASSERT_GT(size, PART_SIZE) << "fixture must span at least two eD2k parts";

  download::PartFile pf(out, size, h->file_hash, h->part_hashes);
  std::ifstream in(source, std::ios::binary);
  ASSERT_TRUE(in.is_open());
  std::vector<std::byte> buf(static_cast<std::size_t>(AICH_BLOCK_SIZE));
  std::uint64_t written = 0;
  while(written < PART_SIZE) {
    const auto n = static_cast<std::size_t>(
      std::min<std::uint64_t>(AICH_BLOCK_SIZE, PART_SIZE - written));
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(n));
    ASSERT_EQ(in.gcount(), static_cast<std::streamsize>(n));
    auto w = pf.write_block(written, written + n, std::span<const std::byte>(buf.data(), n));
    ASSERT_TRUE(w.has_value()) << (w ? "" : w.error().message());
    written += n;
  }

  EXPECT_FALSE(pf.complete());
  EXPECT_TRUE(pf.is_block_done(0, 0));
  EXPECT_FALSE(pf.is_block_done(1, 0));
  EXPECT_TRUE(std::filesystem::exists(out));
  EXPECT_TRUE(std::filesystem::exists(met));
}
