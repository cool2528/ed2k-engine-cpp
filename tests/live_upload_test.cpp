#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/net/packet.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/server/opcodes.hpp"
#include "ed2k/share/known_file.hpp"
#include "ed2k/share/upload_session.hpp"
#include "ed2k/share/upload_throttler.hpp"
#include "ed2k/util/error.hpp"
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

peer::HelloInfo live_hello(std::string_view nickname = "ed2k-live-upload",
                           std::string_view user_hash = "0123456789abcdeffedcba9876543210",
                           std::uint16_t port = 4662) {
  peer::HelloInfo h;
  h.nickname = std::string(nickname);
  h.version = 0x3C;
  h.port = port;
  h.user_hash = *UserHash::from_hex(user_hash);
  return h;
}

UserHash live_user_hash(std::uint64_t seed, std::uint8_t salt) {
  std::array<std::byte, 16> bytes{};
  for(std::size_t i = 0; i < bytes.size(); ++i) {
    const auto shifted = (seed >> ((i % 8) * 8)) & 0xffu;
    bytes[i] = static_cast<std::byte>(shifted ^ (0xa5u + salt + i * 17u));
  }
  return UserHash::from_bytes(bytes);
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
    const auto seed = static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
    const auto holder_hash = live_user_hash(seed, 0x11);
    const auto requester_hash = live_user_hash(seed, 0x42);
    const auto holder_port = static_cast<std::uint16_t>(30000u + (seed % 10000u));
    const auto requester_port = static_cast<std::uint16_t>(holder_port + 1u);

    peer::C2CConnection holder(rt.executor());
    auto holder_cr = co_await holder.connect(source->first, source->second, 15s);
    EXPECT_TRUE(holder_cr.has_value()) << (holder_cr ? "" : holder_cr.error().message());
    if(!holder_cr) co_return;
    auto holder_hs = co_await holder.handshake(live_hello("ed2k-live-holder", holder_hash.to_hex(), holder_port), 15s);
    EXPECT_TRUE(holder_hs.has_value()) << (holder_hs ? "" : holder_hs.error().message());
    if(!holder_hs) co_return;
    auto holder_status = co_await holder.request_file(f->hash, 15s);
    EXPECT_TRUE(holder_status.has_value()) << (holder_status ? "" : holder_status.error().message());
    if(!holder_status) co_return;
    auto holder_start = co_await holder.start_upload(f->hash, 15s);
    EXPECT_TRUE(holder_start.has_value() || holder_start.error() == make_error_code(errc::upload_queued))
      << (holder_start ? "" : holder_start.error().message());
    if(!holder_start && holder_start.error() != make_error_code(errc::upload_queued)) co_return;
    auto holder_name = co_await holder.request_filename(f->hash, 15s);
    EXPECT_TRUE(holder_name.has_value()) << (holder_name ? "" : holder_name.error().message());
    if(!holder_name) co_return;

    peer::C2CConnection c(rt.executor());
    auto cr = co_await c.connect(source->first, source->second, 15s);
    EXPECT_TRUE(cr.has_value()) << (cr ? "" : cr.error().message());
    if(!cr) co_return;
    auto hs = co_await c.handshake(live_hello("ed2k-live-sx2", requester_hash.to_hex(), requester_port), 15s);
    EXPECT_TRUE(hs.has_value()) << (hs ? "" : hs.error().message());
    if(!hs) co_return;
    auto status = co_await c.request_file(f->hash, 15s);
    EXPECT_TRUE(status.has_value()) << (status ? "" : status.error().message());
    if(!status) co_return;
    auto sx = co_await c.request_sources2(f->hash, 15s);
    EXPECT_TRUE(sx.has_value()) << (sx ? "" : sx.error().message());
    if(!sx) co_return;
    EXPECT_EQ(sx->hash, f->hash);
    EXPECT_FALSE(sx->sources.empty());
    EXPECT_TRUE(std::any_of(sx->sources.begin(), sx->sources.end(),
      [&](const peer::PeerSource& src) { return src.user_hash == holder_hash; }));
    c.close();
    holder.close();
    co_return;
  });
}

TEST(LiveUpload, AcceptsLocalPeerUploadSession){
  if(!ed2k::test::live_enabled()) GTEST_SKIP();
  const char* path_s = std::getenv("ED2K_UPLOAD_FILE");
  if(!path_s || !*path_s) GTEST_SKIP() << "set ED2K_UPLOAD_FILE to a file aMule will request";
  const char* port_s = std::getenv("ED2K_UPLOAD_PORT");
  const auto listen_port = port_s && *port_s ? static_cast<std::uint16_t>(std::stoi(port_s)) : 0;
  const char* limit_s = std::getenv("ED2K_UPLOAD_LIMIT_BPS");

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
  std::optional<share::UploadBandwidthThrottler> throttler;
  if(limit_s && *limit_s) {
    throttler.emplace(rt.executor(), static_cast<std::uint64_t>(std::stoull(limit_s)));
  }
  std::printf("  ED2K_UPLOAD_LISTEN=%u\n", listener.local_port());

  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto accepted = co_await listener.accept(120s);
    EXPECT_TRUE(accepted.has_value()) << (accepted ? "" : accepted.error().message());
    if(!accepted) co_return;
    share::UploadSession session(std::move(*accepted), db, live_hello(), rt.disk_executor(), nullptr,
                                 throttler ? &*throttler : nullptr);
    auto r = co_await session.run(120s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });
}

// harness 工具而非断言测试：aMule 仅在 theApp->IsConnected()（已连 eD2k 服务器或 Kad）时才对下载源
// 调用 AskForDownload（aMule 2.3.3 PartFile.cpp Process 的 DS_NONE 分支门控），隔离 harness 里注入的
// 上传源因此永远不被连接。本 stub 应答 LOGINREQUEST→IDCHANGE(HighID) 并保持连接，翻转该门控；
// 其余帧（OFFERFILES/GETSOURCES 等）静默忽略。生命周期由 harness 以 SIGTERM 结束。
TEST(LiveServerStub, ServesAmuleLoginUntilTerminated){
  const char* port_s = std::getenv("ED2K_STUB_PORT");
  if(!port_s || !*port_s) GTEST_SKIP() << "set ED2K_STUB_PORT to serve the local eD2k login stub";
  const auto listen_port = static_cast<std::uint16_t>(std::stoi(port_s));
  using tcp = asio::ip::tcp;

  asio::io_context ctx;
  tcp::acceptor acceptor(ctx, tcp::endpoint(asio::ip::address_v4::any(), listen_port));
  asio::signal_set signals(ctx, SIGINT, SIGTERM);
  signals.async_wait([&](const boost::system::error_code&, int){ ctx.stop(); });
  asio::steady_timer bound(ctx, std::chrono::minutes(15));
  bound.async_wait([&](const boost::system::error_code& e){ if(!e) ctx.stop(); });
  std::printf("  ED2K_STUB_LISTEN=%u\n", acceptor.local_endpoint().port());
  std::fflush(stdout);

  asio::co_spawn(ctx, [&]() -> asio::awaitable<void>{
    for(;;){
      auto [ec, sock] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      asio::co_spawn(ctx, [s = std::move(sock)]() mutable -> asio::awaitable<void>{
        for(;;){
          std::array<std::byte,5> hdr;
          auto [e1, n1] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
          (void)n1; if(e1) co_return;
          auto h = net::parse_header(hdr);
          if(!h || h->size == 0) co_return;
          std::vector<std::byte> body(h->size);
          auto [e2, n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
          (void)n2; if(e2) co_return;
          if(std::to_integer<std::uint8_t>(body[0]) != server::op::LOGINREQUEST) continue;
          // HighID = 客户端自身 IPv4 的 aMule LE 序（首段在低字节）；回 [id:u32][tcpflags:u32=0]
          const std::uint32_t v4 = s.remote_endpoint().address().to_v4().to_uint();
          const std::uint32_t id = ((v4 & 0x000000FFu) << 24) | ((v4 & 0x0000FF00u) << 8) |
                                   ((v4 & 0x00FF0000u) >> 8)  | ((v4 & 0xFF000000u) >> 24);
          codec::ByteWriter w; w.u32(id); w.u32(0);
          net::Packet p; p.protocol = net::proto::eDonkey; p.opcode = server::op::IDCHANGE;
          auto payload = w.take();
          p.payload.assign(payload.begin(), payload.end());
          auto frame = net::encode_frame(p);
          auto [e3, n3] = co_await asio::async_write(s, asio::buffer(frame.data(), frame.size()),
                                                     asio::as_tuple(asio::use_awaitable));
          (void)n3; if(e3) co_return;
        }
      }, asio::detached);
    }
  }, asio::detached);
  ctx.run();
}
