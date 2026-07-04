#include <gtest/gtest.h>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <boost/asio/co_spawn.hpp>
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/share/known_file.hpp"
#include "ed2k/share/upload_session.hpp"
#include "live_env.hpp"

using namespace ed2k;
namespace asio = boost::asio;
using namespace std::chrono_literals;

namespace {
template <class F> static void run_coro(ed2k::net::IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}

std::optional<std::pair<IPv4, std::uint16_t>> env_source() {
  const char* src_s = std::getenv("ED2K_SOURCE");
  if(!src_s || !*src_s) return std::nullopt;
  std::string ss(src_s);
  auto colon = ss.rfind(':');
  if(colon == std::string::npos) return std::nullopt;
  auto ip = IPv4::from_dotted(ss.substr(0, colon));
  if(!ip) return std::nullopt;
  return std::pair{*ip, static_cast<std::uint16_t>(std::stoi(ss.substr(colon + 1)))};
}

peer::HelloInfo live_hello() {
  peer::HelloInfo h;
  h.nickname = "ed2k-live-upload";
  h.version = 0x3C;
  h.port = 4662;
  h.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
  return h;
}

void write_bytes(const std::filesystem::path& p, std::span<const std::byte> data) {
  std::ofstream f(p, std::ios::binary | std::ios::trunc);
  f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}
}

TEST(LiveUpload, SourceExchange2WithLocalPeer){
  if(!ed2k::test::live_enabled()) GTEST_SKIP();
  auto source = env_source();
  if(!source) GTEST_SKIP() << "set ED2K_SOURCE=ip:port for local aMule peer";
  auto ls = ed2k::test::env_link();
  if(ls.empty()) GTEST_SKIP() << "set ED2K_LINK";
  auto pl = parse_link(ls);
  ASSERT_TRUE(pl.has_value());
  auto* f = std::get_if<Ed2kFileLink>(&*pl);
  ASSERT_NE(f, nullptr);

  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    peer::C2CConnection c(rt.executor());
    auto cr = co_await c.connect(source->first, source->second, 15s);
    EXPECT_TRUE(cr.has_value()) << (cr ? "" : cr.error().message());
    if(!cr) co_return;
    auto hs = co_await c.handshake(live_hello(), 15s);
    EXPECT_TRUE(hs.has_value()) << (hs ? "" : hs.error().message());
    if(!hs) co_return;
    auto status = co_await c.request_file(f->hash, 15s);
    EXPECT_TRUE(status.has_value()) << (status ? "" : status.error().message());
    if(!status) co_return;
    auto sx = co_await c.request_sources2(f->hash, 15s);
    EXPECT_TRUE(sx.has_value()) << (sx ? "" : sx.error().message());
    if(!sx) co_return;
    EXPECT_EQ(sx->hash, f->hash);
    c.close();
    co_return;
  });
}

TEST(LiveUpload, AcceptsLocalPeerUploadSession){
  if(!ed2k::test::live_enabled()) GTEST_SKIP();
  const char* path_s = std::getenv("ED2K_UPLOAD_FILE");
  if(!path_s || !*path_s) GTEST_SKIP() << "set ED2K_UPLOAD_FILE to a file aMule will request";
  const char* port_s = std::getenv("ED2K_UPLOAD_PORT");
  const auto listen_port = port_s && *port_s ? static_cast<std::uint16_t>(std::stoi(port_s)) : 0;

  const std::filesystem::path path = path_s;
  if(!std::filesystem::exists(path)) GTEST_SKIP() << "ED2K_UPLOAD_FILE does not exist";
  auto h = hash_file(path, HashVariant::Red);
  ASSERT_TRUE(h.has_value()) << h.error().message();
  auto aich = aich_hash_file(path);
  ASSERT_TRUE(aich.has_value()) << aich.error().message();
  share::KnownFile f;
  f.hash = h->file_hash;
  f.part_hashes = std::move(h->part_hashes);
  f.aich_root = *aich;
  f.name = path.filename().string();
  f.path = path;
  f.size = std::filesystem::file_size(path);

  share::KnownFileDB db;
  db.add(std::move(f));
  ed2k::net::IoRuntime rt;
  peer::InboundListener listener(rt.executor(), listen_port);
  std::printf("  ED2K_UPLOAD_LISTEN=%u\n", listener.local_port());

  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto accepted = co_await listener.accept(120s);
    EXPECT_TRUE(accepted.has_value()) << (accepted ? "" : accepted.error().message());
    if(!accepted) co_return;
    share::UploadSession session(std::move(*accepted), db, live_hello(), rt.disk_executor());
    auto r = co_await session.run(120s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });
}
