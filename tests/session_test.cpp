#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
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
#include "ed2k/server/udp_connection.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/session/session.hpp"
#include "ed2k/util/error.hpp"
#include "crypto/md4.hpp"
#include "mock_peer.hpp"
#include "mock_server.hpp"
#include "mock_udp_server.hpp"
using namespace ed2k; using namespace ed2k::net; using namespace ed2k::app;
using ed2k::server::SourceEndpoint;
using ed2k::session::Session;
using ed2k::session::SessionConfig;
using ed2k::session::TaskState;
using ed2k::session::TaskStateEvent;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;
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
    // 审计 C6: 单次 REQUESTPARTS 最多携带 3 个真实区间(流水线), 逐槽解出后各自回 SENDINGPART
    // (占位槽位 start==end==0 跳过), 而非只读槽0/忽略槽1-2(否则生产侧新的 3-block 批量请求会
    // 卡在等永远不会到来的槽1/槽2 数据, 直到超时)。
    std::array<std::uint32_t,3> rs{}, re{};
    for(auto& v : rs) v = r.u32();
    for(auto& v : re) v = r.u32();
    if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
    for(std::size_t i=0;i<3;++i){
      if(rs[i]==0 && re[i]==0) continue;
      // flat 切片: [rs[i],re[i]) 可能跨 part 边界, 直接从 full 取
      std::size_t off = static_cast<std::size_t>(rs[i]);
      std::size_t len = static_cast<std::size_t>(re[i]-rs[i]);
      codec::ByteWriter w; w.hash16(mf.fhash); w.u32(rs[i]); w.u32(re[i]);
      w.blob(std::span<const std::byte>(full).subspan(off, len));
      co_await send_pkt(s, op::SENDINGPART, w.take());
    }
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
    // 审计 C6: 单次 REQUESTPARTS 最多携带 3 个真实区间(流水线), 逐槽解出后各自延迟 10ms 再回
    // SENDINGPART(占位槽位 start==end==0 跳过), 保持"逐块限速"这一测试语义不变(只是现在一次
    // 请求最多含 3 块, 而非每块单独一次请求)。
    std::array<std::uint32_t,3> rs{}, re{};
    for(auto& v : rs) v = r.u32();
    for(auto& v : re) v = r.u32();
    if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
    for(std::size_t i=0;i<3;++i){
      if(rs[i]==0 && re[i]==0) continue;
      // flat 切片: [rs[i],re[i]) 可能跨 part 边界, 直接从 full 取
      std::size_t off = static_cast<std::size_t>(rs[i]);
      std::size_t len = static_cast<std::size_t>(re[i]-rs[i]);
      asio::steady_timer d(s.get_executor());
      d.expires_after(10ms);
      co_await d.async_wait(asio::use_awaitable);
      codec::ByteWriter w; w.hash16(mf.fhash); w.u32(rs[i]); w.u32(re[i]);
      w.blob(std::span<const std::byte>(full).subspan(off, len));
      co_await send_pkt(s, op::SENDINGPART, w.take());
    }
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

// B6: mock server 应答 LOGIN→IDCHANGE(HighID), GETSOURCES→FOUNDSOURCES(0 个源)——模拟"服务器
// 对这个稀有文件查无结果", 用于驱动 B6a(链接源提示)/B6b(UDP 全局兜底)测试。
static asio::awaitable<void> serve_login_zero_sources(tcp::socket s, const MockFile& mf){
  (void)co_await read_frame(s);
  { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
    co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
  (void)co_await read_frame(s);
  codec::ByteWriter w; w.hash16(mf.fhash); w.u8(0);          // count=0, 无条目
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

// B3 (Task 7): mock server 登录返回 LowID(我方 id<0x1000000) + FOUNDSOURCES 全是 LowID 源。
static asio::awaitable<void> serve_login_lowid_with_lowid_source(tcp::socket s, const MockFile& mf){
  (void)co_await read_frame(s);   // LOGINREQUEST
  { codec::ByteWriter w; w.u32(0x00000119u); w.u32(0x0119u);   // IDCHANGE: id=0x119 < 0x1000000 → 我方 LowID
    co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
  (void)co_await read_frame(s);   // GETSOURCES
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u8(1);
    w.u32(0x00000200u); w.u16(4662);   // 源 id=0x200 < 0x1000000 → LowID 源
    co_await send_pkt(s, ed2k::server::op::FOUNDSOURCES, w.take()); }
  co_await keep_alive(s);
  co_return;
}

// B3: 我方 LowID + 所有源都是 LowID → run_task 必须以 errc::both_lowid 快速失败(不对注定失败的
// LowID 回调白等到 task_io_timeout)。任务未 connect_server, 走 run_task 的轮换登录回退路径,
// self_high_id 取自 login_with_rotation 的 IDCHANGE(此处为 LowID)。
TEST(Session, LowIdSelfAndAllLowIdSourcesFastFailsBothLowId){
  auto mf = make_mock_file(0x55, 0x66);
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_login_lowid_with_lowid_source(std::move(s), mf); co_return; });

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_both_lowid";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.per_server_timeout = 3000ms;
  cfg.task_io_timeout = 20000ms;   // 若未快速失败会一直等回调到这么久; 下方计时断言间接证明是快速失败
  cfg.server_override = ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()};
  Session session(rt, cfg);

  Ed2kFileLink link; link.name="t.bin"; link.size=PART*2; link.hash=mf.fhash;
  auto t0 = std::chrono::steady_clock::now();
  run_coro(rt, [&]() -> asio::awaitable<void>{
    std::uint64_t task_id = session.add_download(link, tmp_dir);
    EXPECT_NE(task_id, 0u);
    asio::steady_timer timer(rt.context());
    for(int i=0;i<200;++i){
      auto snap = session.query(task_id);
      if(snap && snap->state == TaskState::failed) break;
      timer.expires_after(50ms);
      co_await timer.async_wait(asio::use_awaitable);
    }
    auto snap = session.query(task_id);
    EXPECT_TRUE(snap.has_value());
    if(!snap) co_return;
    EXPECT_EQ(snap->state, TaskState::failed);
    EXPECT_EQ(snap->error, make_error_code(ed2k::errc::both_lowid))
        << "we are LowID and every source is LowID → must fast-fail both_lowid";
    co_return;
  });
  auto elapsed = std::chrono::steady_clock::now() - t0;
  EXPECT_LT(elapsed, std::chrono::seconds(10)) << "both_lowid must be a prompt fast-fail, not a timeout wait";
  std::filesystem::remove_all(tmp_dir);
}

// D3(下载 TASK 间端口互斥): 修复前, 两个并发 LowID 下载任务在 run_task 里各自独立 emplace 一个
// InboundListener 绑定 cfg.tcp_port(见修复前 Impl::download_listener_count 注释: "各自独立的
// InboundListener 实例, 靠 SO_REUSEADDR 共存")。这是 D1(单任务内多 worker 回调 crossing)的 TASK
// 级类比: InboundListener 构造设置了 SO_REUSEADDR, Windows 上第二个 acceptor 对同一端口的 bind
// 会静默成功而不是报错, 之后入站连接(源的回拨)被 OS 任意路由给其中一个 acceptor, 另一个任务的
// worker 只能一直等到 task_io_timeout 才失败——本用例复现并证明这个场景已被修复。
//
// 用两个不同的单 part 小文件(内容不同、因而 file_hash 也不同)分别驱动两个并发下载任务, 共享
// 同一个 Session(同一个 cfg.tcp_port)。服务器 mock 按 GETSOURCES 帧里携带的 file hash 区分是
// 哪个任务的连接(而非依赖连接到达顺序——MockServer::serve() 每次调用只 accept 一次, 这里对同一
// acceptor 调用两次 serve(), 两次哪个先接到哪个客户端连接不保证, 见 download_test.cpp
// TransientDropThenReconnectCompletes 的同款说明), 各自应答一个 LowID 源; 收到 CALLBACKREQUEST
// 后从一个独立于 InboundListener 的本地地址真实拨回 cfg.tcp_port(dial-back 地址仅为了两条连接
// 在日志里可辨识, 不参与路由——真实 LowID 回调协议层面拿不到源真实 IP, accept_peer 的
// expected_ip 恒为 nullopt, 见 download.cpp::fetch_hashset 与 inbound_listener.hpp 注释), 用
// serve_lowid_callback_small_file 完整供出"这个任务自己的"文件内容。
//
// 黑盒断言(不新增 Impl 私有访问器, 立场同 session_share_test.cpp 反向门控用例——"listener 是否
// 被二次 bind"本身在 Windows 上不可靠地黑盒探测, 见该用例注释——因此换一个可黑盒观察、确定性的
// 角度证明同一件事):
//  (a) 两个任务都必须收敛到 completed, 而非其中一个 failed(卡到 task_io_timeout)——若端口没有
//      被正确互斥, 至少一个任务的 listener 会因为连接被 OS 路由给另一个 acceptor 而永远等不到
//      回拨连接;
//  (b) 每个任务落盘的文件内容必须与"自己的"源内容逐字节一致——两个源内容不同, 若连接被错配给了
//      另一个任务的 worker, 下载出的内容会是另一个源的字节, 直接比对即可发现。
static asio::awaitable<void> serve_lowid_callback_small_file(tcp::socket s, const FileHash& fhash,
                                                              const std::vector<std::byte>& data){
  using namespace ed2k::peer;
  // initiator 角色: 本连接方向是"LowID 源回拨"(源主动连我方 InboundListener), 我方在
  // accept_peer 里以 acceptor 身份握手(先读 HELLO 再回 HELLOANSWER, 见 download.cpp::
  // fetch_hashset 的 accepted=true 分支), 因此这里(模拟源端)反过来先发 HELLO/EMULEINFO, 再等
  // 对端应答(与 download_test.cpp 里 send_hello_first=true 的 serve_full_peer 重载同构)。
  HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
  co_await send_pkt(s, op::HELLO, encode_hello_packet(h));
  (void)co_await read_frame(s);                          // HELLOANSWER
  { MuleInfo mi; mi.udp_port = 0;
    co_await send_pkt(s, op::EMULEINFO, encode_mule_info(mi), proto::eMule);
    (void)co_await read_frame(s); }                       // EMULEINFOANSWER
  (void)co_await read_frame(s);                           // SETREQFILEID
  { codec::ByteWriter w; w.hash16(fhash); w.u16(0);        // 单 part 文件: 不发 hashset(见 fetch_hashset)
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);                           // REQUESTFILENAME
  { codec::ByteWriter w; w.hash16(fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
    co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
  (void)co_await read_frame(s);                           // STARTUPLOADREQ
  co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});
  for(;;){
    auto body = co_await read_frame(s);                   // REQUESTPARTS
    if(body.empty()){ co_await keep_alive(s); co_return; }
    codec::ByteReader r(std::span<const std::byte>(body).subspan(1));
    (void)r.hash16();
    std::array<std::uint32_t,3> rs{}, re{};
    for(auto& v : rs) v = r.u32();
    for(auto& v : re) v = r.u32();
    if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
    for(std::size_t i=0;i<3;++i){
      if(rs[i]==0 && re[i]==0) continue;
      std::size_t off = rs[i], len = re[i]-rs[i];
      codec::ByteWriter w; w.hash16(fhash); w.u32(rs[i]); w.u32(re[i]);
      w.blob(std::span<const std::byte>(data).subspan(off, len));
      co_await send_pkt(s, op::SENDINGPART, w.take());
    }
  }
}

TEST(Session, ConcurrentLowIdDownloadsDoNotCrossOverSharedPort){
  constexpr std::uint16_t kTestPort = 48191;   // 测试专用固定端口, 与其它用例(48173-48177)不同
  const std::vector<std::byte> data_a(1000, std::byte(0xAA));
  const std::vector<std::byte> data_b(1000, std::byte(0xBB));
  crypto::MD4 ma; ma.update(data_a); const auto fhash_a = FileHash::from_bytes(ma.finish());
  crypto::MD4 mb; mb.update(data_b); const auto fhash_b = FileHash::from_bytes(mb.finish());

  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  auto login_handler = [&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);                          // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);   // IDCHANGE: HighID(我方), 避免 both_lowid 短路
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    auto gs_body = co_await read_frame(s);                  // GETSOURCES: opcode(1)+hash16(16)+size32(4)
    if(gs_body.size() < 17) co_return;
    codec::ByteReader gr(std::span<const std::byte>(gs_body).subspan(1));
    const auto requested_hash = gr.hash16();
    const bool is_a = (requested_hash == fhash_a);
    { codec::ByteWriter w; w.hash16(requested_hash); w.u8(1);
      w.u32(0x00000100u); w.u16(0);                         // 单个 LowID 源(id=0x100, port 回调路径不用)
      co_await send_pkt(s, ed2k::server::op::FOUNDSOURCES, w.take()); }
    auto cb_body = co_await read_frame(s);                  // CALLBACKREQUEST
    const bool got_callback = !cb_body.empty() &&
      std::to_integer<std::uint8_t>(cb_body[0]) == ed2k::server::op::CALLBACKREQUEST;
    if(got_callback){
      asio::co_spawn(s.get_executor(),
        [ex = s.get_executor(), is_a, &fhash_a, &fhash_b, &data_a, &data_b]() -> asio::awaitable<void>{
          tcp::socket c(ex);
          c.open(tcp::v4());
          // bind 到独立于 InboundListener 的本地地址只为了两条连接在日志/抓包里可辨识, 不参与
          // 路由(LowID 回调协议层面拿不到源真实 IP, accept_peer 的 expected_ip 恒为 nullopt)。
          c.bind(tcp::endpoint(asio::ip::make_address_v4(is_a ? "127.0.0.41" : "127.0.0.42"), 0));
          tcp::endpoint ep(asio::ip::make_address_v4("127.0.0.1"), kTestPort);
          auto [ec] = co_await c.async_connect(ep, asio::as_tuple(asio::use_awaitable));
          if(ec) co_return;
          if(is_a) co_await serve_lowid_callback_small_file(std::move(c), fhash_a, data_a);
          else     co_await serve_lowid_callback_small_file(std::move(c), fhash_b, data_b);
          co_return;
        }, asio::detached);
    }
    co_await keep_alive(s);
    co_return;
  };
  srv.serve(login_handler);   // 服务任务 A 的登录连接
  srv.serve(login_handler);   // 服务任务 B 的登录连接(同一 acceptor 上第二次 serve, 各自 accept 一次)

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_concurrent_lowid_ports";
  std::filesystem::remove_all(tmp_dir);
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.tcp_port = kTestPort;
  cfg.per_server_timeout = 3000ms;
  cfg.task_io_timeout = 4000ms;
  cfg.server_override = ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()};
  Session session(rt, cfg);

  Ed2kFileLink link_a; link_a.name = "a.bin"; link_a.size = data_a.size(); link_a.hash = fhash_a;
  Ed2kFileLink link_b; link_b.name = "b.bin"; link_b.size = data_b.size(); link_b.hash = fhash_b;

  std::uint64_t id_a = 0, id_b = 0;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    id_a = session.add_download(link_a, tmp_dir);
    id_b = session.add_download(link_b, tmp_dir);
    EXPECT_NE(id_a, 0u); EXPECT_NE(id_b, 0u);
    asio::steady_timer timer(rt.context());
    for(int i = 0; i < 300; ++i){
      auto sa = session.query(id_a);
      auto sb = session.query(id_b);
      const bool a_done = sa && (sa->state == TaskState::completed || sa->state == TaskState::failed);
      const bool b_done = sb && (sb->state == TaskState::completed || sb->state == TaskState::failed);
      if(a_done && b_done) break;
      timer.expires_after(50ms);
      co_await timer.async_wait(asio::use_awaitable);
    }
    co_return;
  });

  auto snap_a = session.query(id_a);
  auto snap_b = session.query(id_b);
  ASSERT_TRUE(snap_a.has_value());
  ASSERT_TRUE(snap_b.has_value());
  EXPECT_EQ(snap_a->state, TaskState::completed)
      << "task A did not complete: " << snap_a->error.message();
  EXPECT_EQ(snap_b->state, TaskState::completed)
      << "task B did not complete: " << snap_b->error.message();

  if(snap_a->state == TaskState::completed){
    std::ifstream f(tmp_dir / "a.bin", std::ios::binary);
    std::vector<char> got((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    ASSERT_EQ(got.size(), data_a.size());
    EXPECT_TRUE(std::equal(got.begin(), got.end(), reinterpret_cast<const char*>(data_a.data())))
        << "task A's downloaded bytes do not match its own source — crossed with task B's connection";
  }
  if(snap_b->state == TaskState::completed){
    std::ifstream f(tmp_dir / "b.bin", std::ios::binary);
    std::vector<char> got((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    ASSERT_EQ(got.size(), data_b.size());
    EXPECT_TRUE(std::equal(got.begin(), got.end(), reinterpret_cast<const char*>(data_b.data())))
        << "task B's downloaded bytes do not match its own source — crossed with task A's connection";
  }

  std::filesystem::remove_all(tmp_dir);
}

// B2 (Task 7): 单连接依次处理 connect_server 的登录与随后 run_task 在同一连接上发来的 GETSOURCES
// (复用 self->login), 应答含一个 HighID 源的 FOUNDSOURCES。连接空闲窗口(方案 C 快照)期间双方各自
// recv, 靠 connect_server 的快照超时(<=per_server_timeout)打破, 之后 run_task 才发 GETSOURCES。
static asio::awaitable<void> serve_login_then_reused_getsources(tcp::socket s, const MockFile& mf, std::uint16_t peer_port){
  (void)co_await read_frame(s);   // LOGINREQUEST (connect_server)
  { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);   // IDCHANGE: HighID(我方)
    co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
  (void)co_await read_frame(s);   // GETSOURCES (run_task, 复用 self->login 连接)
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u8(1);
    w.u32(0x0100007Fu); w.u16(peer_port);   // HighID 源
    co_await send_pkt(s, ed2k::server::op::FOUNDSOURCES, w.take()); }
  co_await keep_alive(s);
  co_return;
}

// B2: run_task 必须用已连接的搜索服务器(self->login)取源, 而不是新登录一个轮换服务器。让 MockServer
// 只 serve 一个连接: connect_server 建立它; 若 run_task 复用该连接则下载成功, 若另起轮换登录则需要
// 第二个连接(mock 不提供)→ 下载失败。下载成功即证明复用了已连服务器。
TEST(Session, DownloadUsesConnectedSearchServerForSources){
  auto mf = make_mock_file(0x55, 0x66);
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_login_then_reused_getsources(std::move(s), mf, peer.port()); co_return; });

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_use_connected";
  std::filesystem::create_directories(tmp_dir);
  auto out = tmp_dir / "t.bin";
  std::filesystem::remove(out); std::filesystem::remove(out.string()+".part.met");
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.per_server_timeout = 2000ms;   // 快照窗口上限, 尽快进入空闲让 run_task 取源
  cfg.task_io_timeout = 20000ms;
  cfg.server_override = ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()};
  Session session(rt, cfg);

  Ed2kFileLink link; link.name="t.bin"; link.size=PART*2; link.hash=mf.fhash;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto cr = co_await session.connect_server(std::nullopt);   // 建立 self->login = 唯一的 mock 连接
    EXPECT_TRUE(cr.has_value()) << (cr ? "" : cr.error().message());
    if(!cr) co_return;
    std::uint64_t task_id = session.add_download(link, tmp_dir);
    EXPECT_NE(task_id, 0u);
    asio::steady_timer timer(rt.context());
    for(int i=0;i<600;++i){
      auto snap = session.query(task_id);
      if(snap && (snap->state==TaskState::completed || snap->state==TaskState::failed)) break;
      timer.expires_after(50ms);
      co_await timer.async_wait(asio::use_awaitable);
    }
    auto snap = session.query(task_id);
    EXPECT_TRUE(snap.has_value());
    if(!snap) co_return;
    EXPECT_EQ(snap->state, TaskState::completed) << snap->error.message()
        << " (run_task must reuse the connected self->login server for get_sources)";
    co_return;
  });
  ASSERT_TRUE(std::filesystem::exists(out));
  EXPECT_EQ(std::filesystem::file_size(out), PART*2);
  std::filesystem::remove_all(tmp_dir);
}

// 终审 C2 回归: 活动下载期间 disconnect_server 必须不 UAF。run_task/supervisor 持 self->login 的
// shared 副本, disconnect 的 login.reset() 只脱开 Session 的引用, 连接对象由下载副本保活直到下载
// 结束。用慢速 peer(~1.1s 供完整文件)保证下载在 disconnect 时仍活跃; server 每次 GETSOURCES 都应答
// (supervisor 周期重问), disconnect 后 supervisor 会对已 close 的 server 连接反复 get_sources——
// 修复前那是对已析构 ServerConnection 的 UAF, 修复后连接对象仍存活、只是 I/O 失败(优雅)。断言进程
// 不崩且任务收敛到终态。
TEST(Session, DisconnectDuringActiveDownloadDoesNotUseAfterFree){
  auto mf = make_mock_file(0x55, 0x66);
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer_slow(std::move(s), mf); co_return; });
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    for(;;){
      auto body = co_await read_frame(s);   // GETSOURCES (或连接被 disconnect 关闭 → 空帧)
      if(body.empty()) co_return;
      codec::ByteWriter w; w.hash16(mf.fhash); w.u8(1);
      w.u32(0x0100007Fu); w.u16(peer.port());
      co_await send_pkt(s, ed2k::server::op::FOUNDSOURCES, w.take());
    }
  });

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_disconnect_mid_dl";
  std::filesystem::create_directories(tmp_dir);
  auto out = tmp_dir / "t.bin";
  std::filesystem::remove(out); std::filesystem::remove(out.string()+".part.met");
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.per_server_timeout = 2000ms;
  cfg.task_io_timeout = 20000ms;
  cfg.source_reask_interval = 100ms;   // 强制短周期: disconnect 后 supervisor 迅速对已 close 的 conn 发起
                                       // get_sources(真正触发被测的 C2 seam), 而非默认 3 分钟内永不重问
  cfg.server_override = ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()};
  Session session(rt, cfg);

  Ed2kFileLink link; link.name="t.bin"; link.size=PART*2; link.hash=mf.fhash;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto cr = co_await session.connect_server(std::nullopt);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    std::uint64_t task_id = session.add_download(link, tmp_dir);
    asio::steady_timer timer(rt.context());
    for(int i=0;i<200;++i){   // 等进入 downloading(慢速 peer 保证此时下载仍在进行)
      auto snap = session.query(task_id);
      if(snap && snap->state == TaskState::downloading) break;
      timer.expires_after(20ms); co_await timer.async_wait(asio::use_awaitable);
    }
    session.disconnect_server();   // 活动下载期间 reset self->login —— 不得 UAF
    for(int i=0;i<600;++i){        // 等收敛(peer 供完 → completed; 或失败), 只要不崩溃/不挂起
      auto snap = session.query(task_id);
      if(snap && (snap->state==TaskState::completed || snap->state==TaskState::failed)) break;
      timer.expires_after(50ms); co_await timer.async_wait(asio::use_awaitable);
    }
    auto snap = session.query(task_id);
    EXPECT_TRUE(snap.has_value());
    if(!snap) co_return;
    EXPECT_TRUE(snap->state==TaskState::completed || snap->state==TaskState::failed)
        << "task must converge to a terminal state after mid-download disconnect, not hang or UAF-crash";
    co_return;
  });
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

// B6a: 搜索服务器 GETSOURCES 查无结果(serve_login_zero_sources), 链接自带 "s=127.0.0.1:<peer_port>"
// 源提示、且 self->servers 为空(不触发 B6b UDP 兜底)——下载能否完成只取决于 run_task 是否真的把
// 链接内嵌的源提示并入了初始源集合并据此连了那个 peer。
TEST(Session, LinkEmbeddedSourceHintUsedWhenServerReturnsNoSources){
  auto mf = make_mock_file(0x77, 0x88);
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_login_zero_sources(std::move(s), mf); co_return; });

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_link_hint";
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

  Ed2kFileLink link; link.name="t.bin"; link.size=PART*2; link.hash=mf.fhash;
  link.sources.push_back("127.0.0.1:" + std::to_string(peer.port()));   // B6a: 链接内嵌源提示
  std::uint64_t task_id = 0;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    task_id = session.add_download(link, tmp_dir);
    EXPECT_NE(task_id, 0u);
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
    EXPECT_EQ(snap->state, TaskState::completed)
        << snap->error.message() << " (run_task must seed the link-embedded s= source hint)";
    EXPECT_EQ(snap->bytes_done, PART*2);
    EXPECT_EQ(snap->known_sources, 1u);   // 唯一已知源来自链接提示, 而非服务器(服务器回了 0 个)
    co_return;
  });
  ASSERT_TRUE(std::filesystem::exists(out));
  EXPECT_EQ(std::filesystem::file_size(out), PART*2);
  std::filesystem::remove_all(tmp_dir);
}

// B6b: 搜索服务器 GETSOURCES 查无结果(serve_login_zero_sources), 链接不带任何 "s=" 提示(B6a 不
// 参与), 但 self->servers 里有一台已知服务器(经 add_server 注册, 指向下面的 MockUdpServer)——
// 下载能否完成只取决于 run_task 是否真的对该服务器发起了 UDP GLOBGETSOURCES2 并把结果并入源集合。
TEST(Session, UdpGlobalSourcesFallbackUsedWhenServerReturnsNoSources){
  auto mf = make_mock_file(0x99, 0xAA);
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_login_zero_sources(std::move(s), mf); co_return; });

  ed2k::test::MockUdpServer udp_srv(rt.context());
  bool saw_glob_get_sources2 = false;
  udp_srv.serve([&](udp::socket& s, const Packet& request, const udp::endpoint& from) -> asio::awaitable<void>{
    saw_glob_get_sources2 = (request.opcode == ed2k::server::udpop::GLOBGETSOURCES2);
    codec::ByteWriter w; w.hash16(mf.fhash); w.u8(1);
    w.u32(0x0100007Fu); w.u16(peer.port());               // 唯一源: 127.0.0.1:<peer_port> HighID
    co_await ed2k::test::send_packet_to(s, from, ed2k::server::udpop::GLOBFOUNDSOURCES2, w.take());
    co_return;
  });

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_udp_global";
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
  session.add_server(IPv4::from_dotted("127.0.0.1").value(), udp_srv.port(), "udp-fallback-test");

  Ed2kFileLink link; link.name="t.bin"; link.size=PART*2; link.hash=mf.fhash;   // 无 s= 提示: 只测 B6b
  std::uint64_t task_id = 0;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    task_id = session.add_download(link, tmp_dir);
    EXPECT_NE(task_id, 0u);
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
    EXPECT_EQ(snap->state, TaskState::completed)
        << snap->error.message() << " (run_task must fall back to UDP GLOBGETSOURCES2 when the server has zero sources)";
    EXPECT_EQ(snap->bytes_done, PART*2);
    EXPECT_EQ(snap->known_sources, 1u);   // 唯一已知源来自 UDP 全局兜底
    EXPECT_TRUE(saw_glob_get_sources2);
    co_return;
  });
  ASSERT_TRUE(std::filesystem::exists(out));
  EXPECT_EQ(std::filesystem::file_size(out), PART*2);
  std::filesystem::remove_all(tmp_dir);
}

// P2c(Task 9): engine-to-engine 队列/reask 全链路。两个真实 Session: U 分享(max_upload_slots=1,
// 逼迫排队)+ D 下载(极短 peer_reask_interval, 逼真走 UDP reask 保活而非等生产默认 60s)。用一个
// 原始 TCP 客户端(occupier)预占 U 的唯一上传槽位, D 随后连接必然排队而非直接被接受; D 的短
// reask 间隔驱使其在 TCP 静默后发 REASKFILEPING, U 的 UDP 应答器(A8)回 REASKACK(当前排名);
// occupier 断开释放槽位后, U 的 UploadSession 在下一次排队短轮询(A8 的自我提升机制, 见
// upload_session.cpp::run() 实现注释)里发现槽位已空、主动下发 ACCEPTUPLOADREQ, D 的
// queue_wait_phase 据此转入下载、完整拉取多块文件并按内容逐字节比对。
// RED(改动前): U 从不应答 REASKFILEPING(A8 缺失), 也没有任何机制在槽位释放后把排队中的 D
// 晋升为 active(UploadQueue::tick() 生产代码从未调用)——D 会一直排队直到 kQueueWaitMax(30min)
// 才超时放弃, 本用例的完成断言会失败(经 git stash 验证, 见 report)。
TEST(Session, EngineToEngineQueuedDownloadCompletesAfterReaskAndSlotRelease){
  auto share_dir = std::filesystem::temp_directory_path() / "ed2k_e2e_share";
  auto data_dir_u = std::filesystem::temp_directory_path() / "ed2k_e2e_data_u";
  auto data_dir_d = std::filesystem::temp_directory_path() / "ed2k_e2e_data_d";
  std::filesystem::remove_all(share_dir);
  std::filesystem::remove_all(data_dir_u);
  std::filesystem::remove_all(data_dir_d);
  std::filesystem::create_directories(share_dir);
  std::filesystem::create_directories(data_dir_u);
  std::filesystem::create_directories(data_dir_d);

  // ~3.5 个 AICH block(184320B/块, 单 part, 远小于 PART_SIZE): 真正走多次 REQUESTPARTS/
  // SENDINGPART 拉取, 而不是 1 字节文件, 但仍保持测试在 loopback 上快速完成。
  const auto data_size = static_cast<std::size_t>(3 * 184320 + 777);
  std::vector<std::byte> data(data_size);
  { std::uint32_t x = 0xE2E00001u;
    for(std::size_t i = 0; i < data_size; ++i){
      x ^= x << 13; x ^= x >> 17; x ^= x << 5;
      data[i] = std::byte(x & 0xFFu);
    }
  }
  const auto shared_path = share_dir / "e2e_payload.bin";
  { std::ofstream f(shared_path, std::ios::binary|std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size())); }

  IoRuntime rt;

  // Session U: 上传方。max_upload_slots=1 强制排队场景; UDP reask 应答由本任务(A8)提供。
  constexpr std::uint16_t kSessionUPort = 48192;   // 与既有用例(48173-48177, 48191)不同的专用端口
  SessionConfig cfg_u;
  cfg_u.data_dir = data_dir_u;
  cfg_u.tcp_port = kSessionUPort;
  cfg_u.max_upload_slots = 1;
  Session session_u(rt, cfg_u);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    std::vector<std::filesystem::path> dirs{share_dir};
    auto r = co_await session_u.set_shared_dirs(std::move(dirs));
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });
  auto shared = session_u.shared_files();
  ASSERT_EQ(shared.size(), 1u);
  const auto hash = shared[0].hash;
  const auto size = shared[0].size;
  EXPECT_EQ(size, data.size());

  // Session D: 下载方。极短 peer_reask_interval 逼真走 UDP reask 保活(而非等生产默认 60s)。
  // mock 服务器只登录并回 0 源(满足 run_task 的登录前提, 避免误连真实互联网服务器); 真源来自
  // 下面的链接内嵌 s=IP 源提示(B6a, 本 phase Task 6 已落地)。
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    (void)co_await read_frame(s);   // GETSOURCES
    { codec::ByteWriter w; w.hash16(hash); w.u8(0);
      co_await send_pkt(s, ed2k::server::op::FOUNDSOURCES, w.take()); }
    co_await keep_alive(s);
    co_return;
  });

  SessionConfig cfg_d;
  cfg_d.data_dir = data_dir_d;
  cfg_d.per_server_timeout = 3000ms;
  cfg_d.task_io_timeout = 20000ms;
  cfg_d.peer_reask_interval = 200ms;   // 生产默认 60s; 缩短到 200ms 让排队保活在测试时间尺度内发生
  cfg_d.server_override = ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()};
  Session session_d(rt, cfg_d);

  Ed2kFileLink link;
  link.name = "e2e_payload.bin"; link.size = size; link.hash = hash;
  link.sources.push_back("127.0.0.1:" + std::to_string(kSessionUPort));   // B6a: 链接内嵌源提示

  auto out_path = data_dir_d / "e2e_payload.bin";
  std::uint64_t task_id = 0;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    // occupier: 原始 TCP 客户端预占 Session U 的唯一上传槽位(HELLO→STARTUPLOADREQ→
    // ACCEPTUPLOADREQ), 之后长时间静默持有连接不放, 逼迫随后而来的 Session D 真正排队而非
    // 直接被接受。
    tcp::socket occupier(rt.context());
    {
      auto [ec] = co_await occupier.async_connect(
          tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), kSessionUPort), asio::as_tuple(asio::use_awaitable));
      EXPECT_FALSE(ec); if(ec) co_return;
      ed2k::peer::HelloInfo h; h.nickname = "occupier";
      h.user_hash = *UserHash::from_hex("ffffffffffffffffffffffffffffffff");
      co_await send_pkt(occupier, ed2k::peer::op::HELLO, ed2k::peer::encode_hello_packet(h));
      auto hello_ans = co_await read_frame(occupier);
      EXPECT_FALSE(hello_ans.empty()); if(hello_ans.empty()) co_return;
      EXPECT_EQ(std::to_integer<std::uint8_t>(hello_ans[0]), ed2k::peer::op::HELLOANSWER);
      co_await send_pkt(occupier, ed2k::peer::op::STARTUPLOADREQ, ed2k::peer::encode_start_upload(hash));
      auto ans = co_await read_frame(occupier);
      EXPECT_FALSE(ans.empty()); if(ans.empty()) co_return;
      EXPECT_EQ(std::to_integer<std::uint8_t>(ans[0]), ed2k::peer::op::ACCEPTUPLOADREQ);
    }

    task_id = session_d.add_download(link, data_dir_d);
    EXPECT_NE(task_id, 0u);

    // 持有槽位一段时间(>= 2 个 peer_reask_interval 周期), 确保 Session D 真的排队并至少完成
    // 一次真实的 UDP REASKFILEPING/REASKACK 往返(A8), 而不是侥幸抢在它排队之前就释放槽位。
    asio::steady_timer hold(rt.context());
    hold.expires_after(500ms);
    co_await hold.async_wait(asio::use_awaitable);
    occupier.close();   // 释放槽位: 驱动 Session U 的排队短轮询(A8 的自我提升机制)晋升 Session D

    for(int i = 0; i < 600; ++i){
      auto snap = session_d.query(task_id);
      EXPECT_TRUE(snap.has_value());
      if(!snap) co_return;
      if(snap->state == TaskState::completed || snap->state == TaskState::failed) break;
      asio::steady_timer poll(rt.context());
      poll.expires_after(50ms);
      co_await poll.async_wait(asio::use_awaitable);
    }
    auto snap = session_d.query(task_id);
    EXPECT_TRUE(snap.has_value()); if(!snap) co_return;
    EXPECT_EQ(snap->state, TaskState::completed)
        << snap->error.message()
        << " (engine-to-engine queued download must complete via A8 reask-answer + slot-release promotion)";
    EXPECT_EQ(snap->bytes_done, data.size());
    co_return;
  });

  ASSERT_TRUE(std::filesystem::exists(out_path));
  ASSERT_EQ(std::filesystem::file_size(out_path), data.size());
  {
    std::ifstream f(out_path, std::ios::binary);
    std::vector<char> downloaded((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    ASSERT_EQ(downloaded.size(), data.size());
    EXPECT_TRUE(std::equal(downloaded.begin(), downloaded.end(), reinterpret_cast<const char*>(data.data())))
        << "downloaded bytes do not match the shared source file";
  }
  std::filesystem::remove_all(share_dir);
  std::filesystem::remove_all(data_dir_u);
  std::filesystem::remove_all(data_dir_d);
}
