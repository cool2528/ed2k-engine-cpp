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
#include "ed2k/kad/messages.hpp"
#include "ed2k/kad/network.hpp"
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
static asio::awaitable<void> send_pkt(tcp::socket& s, std::uint8_t op, std::span<const std::byte> pl, std::uint8_t proto_val = proto::eDonkey){
  Packet p; p.protocol=proto_val; p.opcode=op; p.payload.assign(pl.begin(),pl.end());
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
  // Task 2: 下载侧握手现无条件跟进 EMULEINFO/EMULEINFOANSWER 交换, mock 必须正确应答,
  // 否则后续真实协议帧会被 pump_until 当噪声吞掉导致会话错位。
  (void)co_await read_frame(s);                          // EMULEINFO
  { MuleInfo mi; mi.udp_port = 4672; co_await send_pkt(s, op::EMULEINFOANSWER, encode_mule_info(mi), proto::eMule); }
  (void)co_await read_frame(s);                          // SETREQFILEID
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u16(2); w.u8(0xFF); w.u8(0x03);  // 两 part 都有
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);                          // HASHSETREQUEST
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u16(2); w.hash16(mf.h0); w.hash16(mf.h1);
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
  }
  co_await keep_alive(s); co_return;
}

TEST(DownloadProgress, ReportsMonotonicProgressToCompletion){
  auto mf = make_mock_file(0x11, 0x22);
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  auto tmp = std::filesystem::temp_directory_path() / "ed2k_progress_test.bin";
  std::filesystem::remove(tmp);
  std::filesystem::remove(tmp.string() + ".part.met");
  std::vector<std::pair<std::uint64_t,std::uint64_t>> calls;   // (done,total) 序列
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = ed2k::download::MultiSourceDownload::Builder(rt.executor())
      .out(tmp).hash(mf.fhash).size(PART*2)
      .sources(std::vector<SourceEndpoint>{{0x0100007Fu, peer.port()}})
      .on_progress([&](std::uint64_t d, std::uint64_t t){ calls.emplace_back(d,t); })
      .build();
    auto r = co_await dl.run(20000ms, 3);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    co_return;
  });
  ASSERT_GE(calls.size(), 2u);                      // 初始一次 + 每块一次
  EXPECT_EQ(calls.front().first, 0u);               // 全新下载初始 done=0
  for(std::size_t i=1;i<calls.size();++i)
    EXPECT_GE(calls[i].first, calls[i-1].first);    // 单调不减
  EXPECT_EQ(calls.back().first, PART*2);            // 完成时 done == total
  EXPECT_EQ(calls.back().second, PART*2);
  std::filesystem::remove(tmp);
  std::filesystem::remove(tmp.string() + ".part.met");
}

TEST(DownloadProgress, StopFlagCancelsRun){
  auto mf = make_mock_file(0x33, 0x44);
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  auto tmp = std::filesystem::temp_directory_path() / "ed2k_stop_test.bin";
  std::filesystem::remove(tmp);
  std::filesystem::remove(tmp.string() + ".part.met");
  auto stop = std::make_shared<bool>(false);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = ed2k::download::MultiSourceDownload::Builder(rt.executor())
      .out(tmp).hash(mf.fhash).size(PART*2)
      .sources(std::vector<SourceEndpoint>{{0x0100007Fu, peer.port()}})
      .on_progress([&](std::uint64_t d, std::uint64_t){ if(d > 0) *stop = true; })  // 首块后请求停止
      .stop_flag(stop)
      .build();
    auto r = co_await dl.run(20000ms, 3);
    // 注: 协程体内不可用裸 return (C++20 规则, ASSERT_* 宏内含 return 无法编译),
    // 故以 EXPECT_FALSE + 条件守卫替代 ASSERT_FALSE, 避免在 r 意外持有值时访问 r.error() 触发 UB。
    EXPECT_FALSE(r.has_value());
    if(!r.has_value()) EXPECT_EQ(r.error(), ed2k::make_error_code(ed2k::errc::cancelled));
    co_return;
  });
  std::filesystem::remove(tmp);
  std::filesystem::remove(tmp.string() + ".part.met");
}
