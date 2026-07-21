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
#include <boost/asio/steady_timer.hpp>
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
#include "ed2k/session/session.hpp"
#include "ed2k/util/error.hpp"
#include "crypto/md4.hpp"
#include "mock_peer.hpp"
#include "mock_server.hpp"
using namespace ed2k; using namespace ed2k::net; using namespace ed2k::app;
using ed2k::server::SourceEndpoint;
using ed2k::session::Session;
using ed2k::session::SessionConfig;
using ed2k::session::TaskState;
using ed2k::session::TaskStateEvent;
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
// (Verbatim pattern from tests/download_test.cpp::serve_full_peer, copied via app_download_test.cpp.)
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

// serve_full_peer 的慢速版: 每次回送 SENDINGPART 前先 sleep 10ms(约 106 块 * 10ms ≈ 1.1s),
// 为 pause 测试留出足够的"downloading 且有进度"观察窗口。
static asio::awaitable<void> serve_full_peer_slow(tcp::socket s, const MockFile& mf){
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
    asio::steady_timer d(s.get_executor());
    d.expires_after(10ms);
    co_await d.async_wait(asio::use_awaitable);
    codec::ByteWriter w; w.hash16(mf.fhash); w.u32(s0); w.u32(e0);
    w.blob(std::span<const std::byte>(full).subspan(off, len));
    co_await send_pkt(s, op::SENDINGPART, w.take());
  }
  co_await keep_alive(s); co_return;
}

// mock server 应答: LOGIN→IDCHANGE(HighID), GETSOURCES→FOUNDSOURCES(1 个 127.0.0.1 HighID 源)
static asio::awaitable<void> serve_login_and_one_source(tcp::socket s, const MockFile& mf, std::uint16_t peer_port){
  (void)co_await read_frame(s);
  { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
    co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
  (void)co_await read_frame(s);
  codec::ByteWriter w; w.hash16(mf.fhash); w.u8(1);
  w.u32(0x0100007Fu); w.u16(peer_port);
  co_await send_pkt(s, ed2k::server::op::FOUNDSOURCES, w.take());
  co_await keep_alive(s);
  co_return;
}

TEST(Session, AddDownloadCompletesWithProgressAndEvents){
  auto mf = make_mock_file(0x55, 0x66);
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_login_and_one_source(std::move(s), mf, peer.port()); co_return; });

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_test";
  std::filesystem::create_directories(tmp_dir);
  auto out = tmp_dir / "t.bin";
  std::filesystem::remove(out);
  std::filesystem::remove(out.string() + ".part.met");

  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.per_server_timeout = 3000ms;
  cfg.task_io_timeout = 20000ms;
  cfg.server_override = ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()};
  Session session(rt, cfg);
  std::vector<TaskState> event_states;
  session.set_event_handler([&](const ed2k::session::SessionEvent& ev){
    if(auto* e = std::get_if<TaskStateEvent>(&ev)) event_states.push_back(e->state);
  });

  Ed2kFileLink link; link.name="t.bin"; link.size=PART*2; link.hash=mf.fhash;
  std::uint64_t task_id = 0;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    task_id = session.add_download(link, tmp_dir);
    EXPECT_NE(task_id, 0u);
    // 轮询直到 completed / failed / 超时
    asio::steady_timer timer(rt.context());
    for(int i=0;i<600;++i){
      auto snap = session.query(task_id);
      EXPECT_TRUE(snap.has_value());
      if(!snap) co_return;
      if(snap->state == TaskState::completed || snap->state == TaskState::failed) break;
      timer.expires_after(50ms);
      co_await timer.async_wait(asio::use_awaitable);
    }
    auto snap = session.query(task_id);
    EXPECT_TRUE(snap.has_value());
    if(!snap) co_return;
    EXPECT_EQ(snap->state, TaskState::completed) << snap->error.message();
    EXPECT_EQ(snap->bytes_done, PART*2);
    EXPECT_EQ(snap->total_size, PART*2);
    EXPECT_EQ(snap->known_sources, 1u);
    co_return;
  });
  ASSERT_TRUE(std::filesystem::exists(out));
  EXPECT_EQ(std::filesystem::file_size(out), PART*2);
  // 事件序列包含 connecting → downloading → completed
  EXPECT_NE(std::find(event_states.begin(), event_states.end(), TaskState::connecting), event_states.end());
  EXPECT_NE(std::find(event_states.begin(), event_states.end(), TaskState::downloading), event_states.end());
  EXPECT_EQ(event_states.back(), TaskState::completed);
  std::filesystem::remove_all(tmp_dir);
}

TEST(Session, QueryAllListsTasksAndUnknownIdReturnsNullopt){
  IoRuntime rt;
  SessionConfig cfg;
  cfg.data_dir = std::filesystem::temp_directory_path();
  Session session(rt, cfg);
  EXPECT_FALSE(session.query(42).has_value());
  EXPECT_TRUE(session.query_all().empty());
}

TEST(Session, PauseResumeCancelLifecycle){
  auto mf = make_mock_file(0x77, 0x88);
  IoRuntime rt;
  // MockPeer/MockServer 的 serve() 只 accept 一次; resume 会触发第二次登录+连接,
  // 这里改用手工 tcp::acceptor 循环 accept(先例见 app_download_test.cpp:196-206)。
  tcp::acceptor peer_acceptor(rt.context(), tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
    for(;;){
      auto [ec, sock] = co_await peer_acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      { boost::system::error_code ndc; sock.set_option(tcp::no_delay(true), ndc); }
      asio::co_spawn(rt.context(),
        [sock = std::move(sock), &mf]() mutable -> asio::awaitable<void>{
          try { co_await serve_full_peer_slow(std::move(sock), mf); } catch(...) {}
          co_return;
        }, asio::detached);
    }
  }, asio::detached);
  tcp::acceptor srv_acceptor(rt.context(), tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  const std::uint16_t peer_port = peer_acceptor.local_endpoint().port();
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
    for(;;){
      auto [ec, sock] = co_await srv_acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      asio::co_spawn(rt.context(),
        [sock = std::move(sock), &mf, peer_port]() mutable -> asio::awaitable<void>{
          try { co_await serve_login_and_one_source(std::move(sock), mf, peer_port); } catch(...) {}
          co_return;
        }, asio::detached);
    }
  }, asio::detached);

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_prc_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.per_server_timeout = 3000ms;
  cfg.task_io_timeout = 20000ms;
  cfg.server_override = ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv_acceptor.local_endpoint().port()};
  Session session(rt, cfg);
  Ed2kFileLink link; link.name="p.bin"; link.size=PART*2; link.hash=mf.fhash;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto id = session.add_download(link, tmp_dir);
    asio::steady_timer timer(rt.context());
    // 等到 downloading 且已有进度
    for(int i=0;i<600;++i){
      auto s = session.query(id);
      if(s && s->state == TaskState::downloading && s->bytes_done > 0) break;
      timer.expires_after(20ms); co_await timer.async_wait(asio::use_awaitable);
    }
    // 协程体内不能用 ASSERT_*(裸 return 非法), 改用 EXPECT_* + co_return 守卫
    bool paused_ok = session.pause(id);
    EXPECT_TRUE(paused_ok);
    if(!paused_ok) co_return;
    EXPECT_EQ(session.query(id)->state, TaskState::paused);
    // 等运行协程退出(active 槽释放): 状态保持 paused 不被覆盖
    timer.expires_after(500ms); co_await timer.async_wait(asio::use_awaitable);
    EXPECT_EQ(session.query(id)->state, TaskState::paused);
    // resume 后重新入队并最终完成(第二连接由手工 acceptor 再次 accept)
    bool resumed_ok = session.resume(id);
    EXPECT_TRUE(resumed_ok);
    if(!resumed_ok) co_return;
    for(int i=0;i<1200;++i){
      auto s = session.query(id);
      if(s && (s->state == TaskState::completed || s->state == TaskState::failed)) break;
      timer.expires_after(50ms); co_await timer.async_wait(asio::use_awaitable);
    }
    EXPECT_EQ(session.query(id)->state, TaskState::completed) << session.query(id)->error.message();
    // cancel(remove_files) 移除任务并删文件
    bool cancelled_ok = session.cancel(id, true);
    EXPECT_TRUE(cancelled_ok);
    if(!cancelled_ok) co_return;
    EXPECT_FALSE(session.query(id).has_value());
    for(int i=0;i<100 && std::filesystem::exists(tmp_dir / "p.bin");++i){
      timer.expires_after(20ms); co_await timer.async_wait(asio::use_awaitable);
    }
    EXPECT_FALSE(std::filesystem::exists(tmp_dir / "p.bin"));
    co_return;
  });
  std::filesystem::remove_all(tmp_dir);
}

// 回归: cancel(remove_files=true) 在下载进行中(协程仍在途, 文件句柄未释放)直接调用时,
// 不能走"立即删除"(Windows 上文件被打开会因 ERROR_SHARING_VIOLATION 静默失败并泄漏),
// 必须走 pending_remove 延迟删除, 待 run_task 协程真正退出(句柄释放)后再删。
// (对比 PauseResumeCancelLifecycle: 那里的 cancel 发生在 completed 之后, 走的是立即删除
//  分支, 未覆盖此延迟删除路径。)
TEST(Session, CancelDownloadingRemovesFilesAfterCoroutineExits){
  auto mf = make_mock_file(0x99, 0xAA);
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer_slow(std::move(s), mf); co_return; });
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_login_and_one_source(std::move(s), mf, peer.port()); co_return; });

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_cancel_inflight_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.per_server_timeout = 3000ms;
  cfg.task_io_timeout = 20000ms;
  cfg.server_override = ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()};
  Session session(rt, cfg);
  Ed2kFileLink link; link.name="q.bin"; link.size=PART*2; link.hash=mf.fhash;
  auto out = tmp_dir / "q.bin";
  auto met = std::filesystem::path(out.string() + ".part.met");
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto id = session.add_download(link, tmp_dir);
    asio::steady_timer timer(rt.context());
    // 等到 downloading 且已有进度(此时协程仍在途, 文件句柄仍打开)
    for(int i=0;i<600;++i){
      auto s = session.query(id);
      if(s && s->state == TaskState::downloading && s->bytes_done > 0) break;
      timer.expires_after(20ms); co_await timer.async_wait(asio::use_awaitable);
    }
    auto snap = session.query(id);
    EXPECT_TRUE(snap.has_value());
    if(!snap) co_return;
    EXPECT_EQ(snap->state, TaskState::downloading);
    EXPECT_GT(snap->bytes_done, 0u);
    bool cancelled_ok = session.cancel(id, true);
    EXPECT_TRUE(cancelled_ok);
    if(!cancelled_ok) co_return;
    EXPECT_FALSE(session.query(id).has_value());   // 任务立即从注册表移除
    // 轮询等待协程真正退出(句柄释放)后文件被删除
    for(int i=0;i<150 && (std::filesystem::exists(out) || std::filesystem::exists(met));++i){
      timer.expires_after(20ms); co_await timer.async_wait(asio::use_awaitable);
    }
    EXPECT_FALSE(std::filesystem::exists(out));
    EXPECT_FALSE(std::filesystem::exists(met));
    co_return;
  });
  std::filesystem::remove_all(tmp_dir);
}

// 回归(原始缺陷的真实触发路径): pause() 只是同步改 state=paused, 并不等旧协程真正退出——
// 旧协程此刻可能仍卡在 co_await dl.run() 里、PartFile 句柄未释放。若 cancel(id,true) 在
// pause 后立即调用(不等旧协程排空), 早期实现会因误判"paused == 已停"走立即删除, 在 Windows
// 上因 ERROR_SHARING_VIOLATION 静默失败并泄漏 .part/.part.met。现改为按 Impl 级在途协程计数
// 判断, 应正确走延迟删除(等最后一个持句柄的协程退出后再删)。
TEST(Session, CancelPausedRemovesFilesAfterCoroutineExits){
  auto mf = make_mock_file(0xBB, 0xCC);
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer_slow(std::move(s), mf); co_return; });
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_login_and_one_source(std::move(s), mf, peer.port()); co_return; });

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_cancel_paused_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.per_server_timeout = 3000ms;
  cfg.task_io_timeout = 20000ms;
  cfg.server_override = ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()};
  Session session(rt, cfg);
  Ed2kFileLink link; link.name="r.bin"; link.size=PART*2; link.hash=mf.fhash;
  auto out = tmp_dir / "r.bin";
  auto met = std::filesystem::path(out.string() + ".part.met");
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto id = session.add_download(link, tmp_dir);
    asio::steady_timer timer(rt.context());
    // 等到 downloading 且已有进度(此时协程仍在途, 文件句柄仍打开)
    for(int i=0;i<600;++i){
      auto s = session.query(id);
      if(s && s->state == TaskState::downloading && s->bytes_done > 0) break;
      timer.expires_after(20ms); co_await timer.async_wait(asio::use_awaitable);
    }
    auto snap = session.query(id);
    EXPECT_TRUE(snap.has_value());
    if(!snap) co_return;
    EXPECT_EQ(snap->state, TaskState::downloading);
    EXPECT_GT(snap->bytes_done, 0u);
    bool paused_ok = session.pause(id);
    EXPECT_TRUE(paused_ok);
    if(!paused_ok) co_return;
    // 关键: 不等待(不 sleep), 立即 cancel — 复现"旧协程尚未排空即 cancel"的竞态窗口
    bool cancelled_ok = session.cancel(id, true);
    EXPECT_TRUE(cancelled_ok);
    if(!cancelled_ok) co_return;
    EXPECT_FALSE(session.query(id).has_value());
    for(int i=0;i<200 && (std::filesystem::exists(out) || std::filesystem::exists(met));++i){
      timer.expires_after(20ms); co_await timer.async_wait(asio::use_awaitable);
    }
    EXPECT_FALSE(std::filesystem::exists(out));
    EXPECT_FALSE(std::filesystem::exists(met));
    co_return;
  });
  std::filesystem::remove_all(tmp_dir);
}

// 回归: pause 后立即(不等旧协程退出) resume, 制造"新旧两代 run_task 协程同时在途"的竞态
// 窗口(旧代挂起在某个 co_await 上尚未醒来, 新代已被 pump() spawn 启动)。此时若再 cancel,
// 必须等两代协程都退出(在途计数归零)才能安全删文件, 否则较早退出的一代会误清空计数,
// 让另一代仍持有句柄时就被判定为"可以立即删"。
TEST(Session, PauseResumeCancelRemovesFiles){
  auto mf = make_mock_file(0xDD, 0xEE);
  IoRuntime rt;
  // resume 会触发第二次登录+连接, 手工 tcp::acceptor 循环 accept(先例见 app_download_test.cpp:196-206)。
  tcp::acceptor peer_acceptor(rt.context(), tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
    for(;;){
      auto [ec, sock] = co_await peer_acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      { boost::system::error_code ndc; sock.set_option(tcp::no_delay(true), ndc); }
      asio::co_spawn(rt.context(),
        [sock = std::move(sock), &mf]() mutable -> asio::awaitable<void>{
          try { co_await serve_full_peer_slow(std::move(sock), mf); } catch(...) {}
          co_return;
        }, asio::detached);
    }
  }, asio::detached);
  tcp::acceptor srv_acceptor(rt.context(), tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  const std::uint16_t peer_port = peer_acceptor.local_endpoint().port();
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
    for(;;){
      auto [ec, sock] = co_await srv_acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      asio::co_spawn(rt.context(),
        [sock = std::move(sock), &mf, peer_port]() mutable -> asio::awaitable<void>{
          try { co_await serve_login_and_one_source(std::move(sock), mf, peer_port); } catch(...) {}
          co_return;
        }, asio::detached);
    }
  }, asio::detached);

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_pause_resume_cancel_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.per_server_timeout = 3000ms;
  cfg.task_io_timeout = 20000ms;
  cfg.server_override = ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv_acceptor.local_endpoint().port()};
  Session session(rt, cfg);
  Ed2kFileLink link; link.name="s.bin"; link.size=PART*2; link.hash=mf.fhash;
  auto out = tmp_dir / "s.bin";
  auto met = std::filesystem::path(out.string() + ".part.met");
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto id = session.add_download(link, tmp_dir);
    asio::steady_timer timer(rt.context());
    for(int i=0;i<600;++i){
      auto s = session.query(id);
      if(s && s->state == TaskState::downloading && s->bytes_done > 0) break;
      timer.expires_after(20ms); co_await timer.async_wait(asio::use_awaitable);
    }
    auto snap = session.query(id);
    EXPECT_TRUE(snap.has_value());
    if(!snap) co_return;
    EXPECT_EQ(snap->state, TaskState::downloading);
    EXPECT_GT(snap->bytes_done, 0u);
    bool paused_ok = session.pause(id);
    EXPECT_TRUE(paused_ok);
    if(!paused_ok) co_return;
    // 关键: 不等待旧协程排空, 立即 resume — 制造新旧两代协程同时在途的竞态窗口
    bool resumed_ok = session.resume(id);
    EXPECT_TRUE(resumed_ok);
    if(!resumed_ok) co_return;
    // 等新一代重新进入 downloading(第二次连接由手工 acceptor 再次 accept)
    for(int i=0;i<600;++i){
      auto s = session.query(id);
      if(s && s->state == TaskState::downloading && s->bytes_done > 0) break;
      timer.expires_after(20ms); co_await timer.async_wait(asio::use_awaitable);
    }
    snap = session.query(id);
    EXPECT_TRUE(snap.has_value());
    if(!snap) co_return;
    EXPECT_EQ(snap->state, TaskState::downloading);
    bool cancelled_ok = session.cancel(id, true);
    EXPECT_TRUE(cancelled_ok);
    if(!cancelled_ok) co_return;
    EXPECT_FALSE(session.query(id).has_value());
    for(int i=0;i<300 && (std::filesystem::exists(out) || std::filesystem::exists(met));++i){
      timer.expires_after(20ms); co_await timer.async_wait(asio::use_awaitable);
    }
    EXPECT_FALSE(std::filesystem::exists(out));
    EXPECT_FALSE(std::filesystem::exists(met));
    co_return;
  });
  std::filesystem::remove_all(tmp_dir);
}
