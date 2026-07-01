#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
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
#include "ed2k/download/download.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/server/opcodes.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/util/error.hpp"
#include "crypto/md4.hpp"
#include "mock_peer.hpp"
#include "mock_server.hpp"
using namespace ed2k; using namespace ed2k::net; using namespace ed2k::app;
using ed2k::server::SourceEndpoint;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;
static constexpr std::uint64_t PART = 9728000;

template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}
static std::vector<std::byte> bytes(std::initializer_list<int> xs){
  std::vector<std::byte> v; for(int x:xs) v.push_back(std::byte(x)); return v;
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

// mock peer 提供一个 2-part 文件,part 数据由 fill 决定
struct MockFile { std::vector<std::byte> d0, d1; PartHash h0, h1; FileHash fhash; };
static MockFile make_mock_file(std::uint8_t f0, std::uint8_t f1){
  MockFile mf;
  mf.d0.assign(PART, std::byte(f0)); mf.d1.assign(PART, std::byte(f1));
  crypto::MD4 m; m.update(mf.d0); mf.h0 = PartHash::from_bytes(m.finish());
  m = {}; m.update(mf.d1); mf.h1 = PartHash::from_bytes(m.finish());
  // file hash = MD4(h0 || h1)
  m = {}; m.update(mf.h0.bytes()); m.update(mf.h1.bytes()); mf.fhash = FileHash::from_bytes(m.finish());
  return mf;
}

// peer 响应 Download 的请求序列:HELLO→FILESTATUS→HASHSET→FILENAME→ACCEPT→
// 循环处理 REQUESTPARTS:解析请求范围,回送对应字节切片 + OUTOFPARTREQS 终止多响应循环。
// 请求范围 [s0,e0) 是 flat 整文件块, 可能跨越 part 边界: 从 full=d0||d1 切片即可。
// (Verbatim pattern from tests/download_test.cpp::serve_full_peer — authoritative per task brief.)
static asio::awaitable<void> serve_full_peer(tcp::socket s, const MockFile& mf){
  using namespace ed2k::peer;
  std::vector<std::byte> full;
  full.insert(full.end(), mf.d0.begin(), mf.d0.end());
  full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  (void)co_await read_frame(s);                          // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  (void)co_await read_frame(s);                          // SETREQFILEID
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u16(2); w.u8(0xFF); w.u8(0x03);  // 两 part 都有
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);                          // HASHSETREQUEST
  { codec::ByteWriter w; w.u16(2); w.hash16(mf.h0); w.hash16(mf.h1);
    co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
  (void)co_await read_frame(s);                          // REQUESTFILENAME
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
    co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
  (void)co_await read_frame(s); co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});  // STARTUPLOADREQ
  for(;;){
    auto body = co_await read_frame(s);                  // REQUESTPARTS
    if(body.empty()){ co_await keep_alive(s); co_return; }
    codec::ByteReader r(std::span<const std::byte>(body).subspan(1));  // 跳过 opcode
    (void)r.hash16();                                    // 文件 hash
    std::uint32_t s0=r.u32(), s1=r.u32(), s2=r.u32();
    std::uint32_t e0=r.u32(), e1=r.u32(), e2=r.u32();
    (void)s1;(void)s2;(void)e1;(void)e2;
    if(s0==0 && e0==0){ co_await keep_alive(s); co_return; }
    // flat 切片: [s0,e0) 可能跨 part 边界, 直接从 full 取
    std::size_t off = static_cast<std::size_t>(s0);
    std::size_t len = static_cast<std::size_t>(e0 - s0);
    codec::ByteWriter w; w.hash16(mf.fhash); w.u32(s0); w.u32(e0);
    w.blob(std::span<const std::byte>(full).subspan(off, len));
    co_await send_pkt(s, op::SENDINGPART, w.take());
    co_await send_pkt(s, op::OUTOFPARTREQS, {});         // 终止 request_blocks 多响应循环
  }
  co_await keep_alive(s); co_return;
}

TEST(AppDownload, FilterHighIdDropsLowId){
  std::vector<SourceEndpoint> srcs = { {0x01000000u,4662}, {5u,4662}, {0x02000000u,4662} };
  auto hi = filter_high_id(srcs);
  EXPECT_EQ(hi.size(), 2u);
  for(const auto& s : hi) EXPECT_FALSE(s.low_id());
}

TEST(AppDownload, EndToEndHighIdMockDownload){
  auto mf = make_mock_file(0x11, 0x22);
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, server::op::IDCHANGE, w.take()); }
    (void)co_await read_frame(s);   // GETSOURCES
    // FOUNDSOURCES: file_hash(16) + u8 count(1) + src(id=127.0.0.1 HighID, port=peer.port)
    // count is u8 (decode_found_sources reads u8); source id MUST be 127.0.0.1 (0x7F000001)
    // so MultiSourceDownload connects to the local MockPeer (peer_worker does IPv4{source.id}).
    codec::ByteWriter w; w.hash16(mf.fhash); w.u8(1);
    w.u32(0x7F000001u); w.u16(peer.port());
    co_await send_pkt(s, server::op::FOUNDSOURCES, w.take());
    co_await keep_alive(s);
    co_return;
  });
  Ed2kFileLink link; link.name="t"; link.size=PART*2; link.hash=mf.fhash;
  ServerList sl; ServerEntry sv; sv.ip=IPv4::from_dotted("127.0.0.1").value(); sv.port=srv.port(); sl.servers={sv};
  auto metbytes = write_server_met(sl);
  auto tmp = std::filesystem::temp_directory_path() / "ed2k_app_dl_test";
  std::filesystem::remove(tmp);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    DownloadOpts o; o.out_path=tmp; o.per_server_timeout=3000ms; o.total_timeout=20000ms;
    auto r = co_await download_link(rt.executor(), link, metbytes,
      ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()}, o);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    co_return;
  });
  // 校验文件存在 + size == PART*2 (内容已由 PartFile part-MD4 校验保证)
  ASSERT_TRUE(std::filesystem::exists(tmp));
  EXPECT_EQ(std::filesystem::file_size(tmp), PART*2);
  std::filesystem::remove(tmp);
}

// Regression (Task-7 fix): a HighID-only download_link must NOT construct an
// InboundListener, so it must still succeed when opts.client_port is already
// (exclusively) bound by another socket. Pre-fix, InboundListener(ex,port) was
// constructed unconditionally and its ctor threw boost::system::system_error on
// the occupied port (asio's 2-arg acceptor ctor cannot share a port held under
// SO_EXCLUSIVEADDRUSE), failing the HighID path even though the listener is
// never used for HighID sources. Post-fix the listener is constructed lazily
// (only when a LowID source is present), so HighID-only download completes.
TEST(AppDownload, HighIdOnlySucceedsWhenClientPortBound){
  auto mf = make_mock_file(0x33, 0x44);
  IoRuntime rt;
  // Exclusively occupy a free port. SO_EXCLUSIVEADDRUSE must be set before bind
  // and defeats the SO_REUSEADDR that asio's 2-arg acceptor ctor sets by default
  // (so InboundListener's ctor cannot share the port -> throws pre-fix).
  tcp::acceptor occ(rt.context());
  occ.open(tcp::v4());
#ifdef _WIN32
  {
    BOOL excl = TRUE;
    int sr = ::setsockopt(occ.native_handle(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                          reinterpret_cast<const char*>(&excl), sizeof(excl));
    ASSERT_NE(sr, SOCKET_ERROR) << "setsockopt(SO_EXCLUSIVEADDRUSE) failed";
  }
#endif
  occ.bind(tcp::endpoint(asio::ip::address_v4::any(), 0));
  occ.listen();
  std::uint16_t occupied = occ.local_endpoint().port();

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, server::op::IDCHANGE, w.take()); }
    (void)co_await read_frame(s);   // GETSOURCES
    // HighID-only source: 127.0.0.1 (0x7F000001, id >= 0x1000000) -> !low_id().
    codec::ByteWriter w; w.hash16(mf.fhash); w.u8(1);
    w.u32(0x7F000001u); w.u16(peer.port());
    co_await send_pkt(s, server::op::FOUNDSOURCES, w.take());
    co_await keep_alive(s);
    co_return;
  });
  Ed2kFileLink link; link.name="t"; link.size=PART*2; link.hash=mf.fhash;
  ServerList sl; ServerEntry sv; sv.ip=IPv4::from_dotted("127.0.0.1").value(); sv.port=srv.port(); sl.servers={sv};
  auto metbytes = write_server_met(sl);
  auto tmp = std::filesystem::temp_directory_path() / "ed2k_app_dl_portbound_test";
  std::filesystem::remove(tmp);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    DownloadOpts o; o.out_path=tmp; o.client_port=occupied;
    o.per_server_timeout=3000ms; o.total_timeout=20000ms;
    auto r = co_await download_link(rt.executor(), link, metbytes,
      ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()}, o);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;
    co_return;
  });
  ASSERT_TRUE(std::filesystem::exists(tmp));
  EXPECT_EQ(std::filesystem::file_size(tmp), PART*2);
  std::filesystem::remove(tmp);
}

// Regression (I1 fix): when a LowID source is present, download_link attempts to
// construct InboundListener(opts.client_port). If that port is already (exclusively)
// bound, the InboundListener ctor throws boost::system::system_error. Pre-fix the
// throw propagated out of the expected<> coroutine (CLI spawns it asio::detached
// with no handler) -> std::terminate, violating spec §6.1 ("无异常/CLI 不崩").
// Post-fix the throw is contained at the call site: listener stays empty, peer_worker's
// LowID branch returns connect_failed (defensive `!listener` guard) -> LowID source is
// skipped gracefully, and a following HighID source completes the download normally.
TEST(AppDownload, LowIdSourceSkipsGracefullyWhenClientPortBound){
  auto mf = make_mock_file(0x55, 0x66);
  IoRuntime rt;
  // Exclusively occupy a free port (same technique as HighIdOnlySucceedsWhenClientPortBound).
  tcp::acceptor occ(rt.context());
  occ.open(tcp::v4());
#ifdef _WIN32
  {
    BOOL excl = TRUE;
    int sr = ::setsockopt(occ.native_handle(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                          reinterpret_cast<const char*>(&excl), sizeof(excl));
    ASSERT_NE(sr, SOCKET_ERROR) << "setsockopt(SO_EXCLUSIVEADDRUSE) failed";
  }
#endif
  occ.bind(tcp::endpoint(asio::ip::address_v4::any(), 0));
  occ.listen();
  std::uint16_t occupied = occ.local_endpoint().port();

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, server::op::IDCHANGE, w.take()); }
    (void)co_await read_frame(s);   // GETSOURCES
    // FOUNDSOURCES: file_hash(16) + u8 count(2) + src0(LowID id=0x100 <0x1000000, port=0)
    //   + src1(HighID id=127.0.0.1=0x7F000001, port=peer.port()). LowID first so the
    //   skipped path is exercised before the completing HighID source.
    codec::ByteWriter w; w.hash16(mf.fhash); w.u8(2);
    w.u32(0x00000100u); w.u16(0);              // LowID source (callback path, skipped)
    w.u32(0x7F000001u); w.u16(peer.port());    // HighID source (completes the download)
    co_await send_pkt(s, server::op::FOUNDSOURCES, w.take());
    co_await keep_alive(s);
    co_return;
  });
  Ed2kFileLink link; link.name="t"; link.size=PART*2; link.hash=mf.fhash;
  ServerList sl; ServerEntry sv; sv.ip=IPv4::from_dotted("127.0.0.1").value(); sv.port=srv.port(); sl.servers={sv};
  auto metbytes = write_server_met(sl);
  auto tmp = std::filesystem::temp_directory_path() / "ed2k_app_dl_lowid_portbound_test";
  std::filesystem::remove(tmp);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    DownloadOpts o; o.out_path=tmp; o.client_port=occupied;
    o.per_server_timeout=3000ms; o.total_timeout=20000ms;
    auto r = co_await download_link(rt.executor(), link, metbytes,
      ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()}, o);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;
    co_return;
  });
  // LowID skipped (listener null) + HighID completed -> file exists with full size.
  ASSERT_TRUE(std::filesystem::exists(tmp));
  EXPECT_EQ(std::filesystem::file_size(tmp), PART*2);
  std::filesystem::remove(tmp);
}
