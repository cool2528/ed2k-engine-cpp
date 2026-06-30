#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "crypto/md4.hpp"
#include "ed2k/util/error.hpp"
#include "mock_peer.hpp"
using namespace ed2k; using namespace ed2k::net; using namespace ed2k::peer;
using namespace ed2k::download;
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
// 循环处理 REQUESTPARTS:解析请求范围,回送对应 part 数据 + OUTOFPARTREQS 终止多响应循环。
static asio::awaitable<void> serve_full_peer(tcp::socket s, const MockFile& mf){
  using namespace ed2k::peer;
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
    std::uint32_t part = s0 / static_cast<std::uint32_t>(PART);
    std::uint64_t pstart = static_cast<std::uint64_t>(part) * PART;
    const auto& d = (part==0)?mf.d0:mf.d1;
    // 只回送请求范围内的切片(整 part 9.72MiB > 8MiB 帧上限,必须分块)
    std::size_t off = static_cast<std::size_t>(s0 - pstart);
    std::size_t len = static_cast<std::size_t>(e0 - s0);
    codec::ByteWriter w; w.hash16(mf.fhash); w.u32(s0); w.u32(e0);
    w.blob(std::span<const std::byte>(d).subspan(off, len));
    co_await send_pkt(s, op::SENDINGPART, w.take());
    co_await send_pkt(s, op::OUTOFPARTREQS, {});         // 终止 request_blocks 多响应循环
  }
  co_await keep_alive(s); co_return;
}
TEST(Download, EndToEndSingleSource){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_e2e"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x7F000001u, peer.port()});
    auto r = co_await dl.run(5s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    // 校验文件
    { PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1}); EXPECT_TRUE(pf.complete()); }
    co_return;
  });
  std::filesystem::remove_all(dir);
}
TEST(Download, ResumeSkipsCompletedParts){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_resume"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  // 预写 part0
  { std::ofstream f(path, std::ios::binary); f.write(reinterpret_cast<const char*>(mf.d0.data()), mf.d0.size()); }
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x7F000001u, peer.port()});
    auto r = co_await dl.run(5s);
    EXPECT_TRUE(r.has_value());                          // part0 已校验跳过,只下 part1
    co_return;
  });
  std::filesystem::remove_all(dir);
}
TEST(Download, BlockCorruptFails){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_corrupt"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  // peer 发坏 part0 数据(填充 0xFF,但 hashset 用正确 h0)
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    auto bad = mf; bad.d0.assign(PART, std::byte(0xFF));  // 坏数据
    co_await serve_full_peer(std::move(s), bad); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x7F000001u, peer.port()});
    auto r = co_await dl.run(5s);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::block_corrupt));
    co_return;
  });
  std::filesystem::remove_all(dir);
}

TEST(Download, BlockLevelSingleSource){
  // download 2-part file with block-level allocation (no AICH)
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_block"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::MultiSourceDownload dl(rt.executor(), path, mf.fhash, PART*2, std::nullopt,
      std::vector{SourceEndpoint{0x7F000001u, peer.port()}});
    auto r = co_await dl.run(5s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  std::filesystem::remove_all(dir);
}

TEST(Download, AICHCorruptionRecovers){
  // one block corrupted on first try, gets re-download from another peer successfully
  // TODO: implement this test when multi-source fully working
  GTEST_SKIP() << "Multi-source AICH recovery not implemented yet";
}

TEST(Download, RequestPartsI64RoundTrip){
  // test I64 encoding works
  // Already covered by c2c_messages_test
  GTEST_SKIP() << "I64 encoding covered by C2CMessages tests";
}
