#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <functional>
#include <optional>
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
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/server/opcodes.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/server/search_query.hpp"
#include "ed2k/session/session.hpp"
#include "ed2k/util/error.hpp"
#include "mock_server.hpp"
using namespace ed2k; using namespace ed2k::net;
using ed2k::session::Session;
using ed2k::session::SessionConfig;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
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

TEST(SessionServer, ConnectEmitsStateAndDisconnectClears){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    co_await keep_alive(s);
    co_return;
  });
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_srv_test";
  std::filesystem::create_directories(tmp_dir);
  // 方案 C: connect_server 在 login 后会同步读一个 min(per_server_timeout, 2s) 的初始快照窗口
  // (mock 在此用例里发完 IDCHANGE 后不再推送任何内容); 把 per_server_timeout 设小, 让不关心
  // 快照内容的用例快速跑完窗口, 而不是每次都白等到 2s 上限。
  SessionConfig cfg; cfg.data_dir = tmp_dir; cfg.per_server_timeout = 100ms;
  Session session(rt, cfg);
  std::vector<ed2k::session::ServerStateEvent> events;
  session.set_event_handler([&](const ed2k::session::SessionEvent& ev){
    if(auto* e = std::get_if<ed2k::session::ServerStateEvent>(&ev)) events.push_back(*e);
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await session.connect_server(
      ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()});
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;                     // 协程体内禁用 ASSERT_*; 失败时守卫式提前返回
    EXPECT_TRUE(r->high_id);
    EXPECT_TRUE(session.server_connected());
    session.disconnect_server();
    EXPECT_FALSE(session.server_connected());
    co_return;
  });
  ASSERT_GE(events.size(), 2u);
  EXPECT_TRUE(events.front().connected);
  EXPECT_FALSE(events.back().connected);
  std::filesystem::remove_all(tmp_dir);
}

TEST(SessionServer, AddRemovePersistsServerMet){
  IoRuntime rt;
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_met_test";
  std::filesystem::remove_all(tmp_dir);
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg; cfg.data_dir = tmp_dir;
  {
    Session session(rt, cfg);
    EXPECT_TRUE(session.add_server(IPv4::from_dotted("10.0.0.1").value(), 4661, "alpha"));
    EXPECT_FALSE(session.add_server(IPv4::from_dotted("10.0.0.1").value(), 4661, "alpha"));  // 去重
    EXPECT_EQ(session.server_list().size(), 1u);
  }
  {
    Session session2(rt, cfg);                       // 重新加载 server.met
    auto list = session2.server_list();
    ASSERT_EQ(list.size(), 1u);
    EXPECT_EQ(list[0].port, 4661);
    EXPECT_TRUE(session2.remove_server(list[0].ip, list[0].port));
    EXPECT_TRUE(session2.server_list().empty());
  }
  std::filesystem::remove_all(tmp_dir);
}

// 方案 C(替代原 C1 回归用例): connect_server 不再启动常驻 receive_loop——仅在 login 后同步读一个
// min(per_server_timeout, 2s) 的初始快照窗口, 窗口结束后连接转入空闲, 不再有任何协程持续读取
// (消除了它与前台请求 search()/get_sources() 并发读同一 socket 的根源)。这是有意接受的降级:
// Session 不再主动检测服务器掉线, 只会在下一次前台请求因连接已失效而失败时才发现。
// mock server 发完 IDCHANGE 后只保持连接打开、不再推送/不关闭(快照窗口读满 per_server_timeout
// 后自然结束); 之后连接空闲一段时间(跨越好几个 per_server_timeout 周期), 由于没有任何主动检测
// 机制, server_connected() 必须恒为 true, 且不应该产生任何 spurious disconnected 事件。
TEST(SessionServer, RemainsConnectedWhileIdleWithNoActiveReader){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    co_await keep_alive(s);         // 保持连接打开、不再推送、不关闭
    co_return;
  });
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_srv_idle_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg; cfg.data_dir = tmp_dir; cfg.per_server_timeout = 300ms;
  Session session(rt, cfg);
  std::vector<ed2k::session::ServerStateEvent> events;
  session.set_event_handler([&](const ed2k::session::SessionEvent& ev){
    if(auto* e = std::get_if<ed2k::session::ServerStateEvent>(&ev)) events.push_back(*e);
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await session.connect_server(
      ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()});
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;                     // 协程体内禁用 ASSERT_*; 失败时守卫式提前返回
    EXPECT_TRUE(session.server_connected());
    // 跨越约 3 个 per_server_timeout 周期静默等待, 期间连接完全空闲(无任何协程读取该 socket)。
    asio::steady_timer timer(rt.context());
    timer.expires_after(cfg.per_server_timeout * 3);
    co_await timer.async_wait(asio::use_awaitable);
    // 方案 C: 没有常驻读者主动检测断线, 纯本地状态位在空闲期间恒为 true。
    EXPECT_TRUE(session.server_connected());
    session.disconnect_server();
    co_return;
  });
  // 期望恰好两条事件: connect 时的 connected=true, 以及测试末尾主动 disconnect 的 connected=false。
  // 空闲期间不应产生任何额外事件(既没有常驻读者, 也就不会有 spurious disconnected)。
  ASSERT_EQ(events.size(), 2u);
  EXPECT_TRUE(events.front().connected);
  EXPECT_FALSE(events.back().connected);
  std::filesystem::remove_all(tmp_dir);
}

// 回归(C2): connect_server 收到的 ServerIdentEvent 除 name 外还带着服务器自报的 ip/port——
// login_with_rotation 可能故障转移到 target 之外的服务器, 因此最终 server_state 的 ip/port
// 必须以 ServerIdentEvent 的值为准, 而不是停留在最初连接请求的 target 占位值上。
// 方案 C: mock server 在 IDCHANGE 后紧接着发 SERVERIDENT, 落在 connect_server 的初始快照窗口
// 内, 会在 connect_server 返回前同步处理完毕(收到 Ident 后窗口提前结束), 不再需要额外等待。
TEST(SessionServer, IdentUpdatesServerAddress){
  IoRuntime rt;
  const auto ident_ip = IPv4::from_dotted("203.0.113.7").value();   // 刻意不同于 target(127.0.0.1)
  const std::uint16_t ident_port = 5555;                            // 刻意不同于 target 的 srv.port()
  const std::string ident_name = "real-server";
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    { codec::ByteWriter w;
      w.hash16(MD4Hash{});
      w.u32_be(ident_ip.host());
      w.u16(ident_port);
      codec::Tag name_tag; name_tag.name_id = ed2k::server::tag::ST_SERVERNAME; name_tag.value = ident_name;
      std::vector<codec::Tag> tags{name_tag};
      w.u32(static_cast<std::uint32_t>(tags.size()));
      codec::write_taglist(w, tags);
      co_await send_pkt(s, ed2k::server::op::SERVERIDENT, w.take());
    }
    co_await keep_alive(s);
    co_return;
  });
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_srv_ident_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg; cfg.data_dir = tmp_dir; cfg.per_server_timeout = 3000ms;
  Session session(rt, cfg);
  std::vector<ed2k::session::ServerStateEvent> events;
  session.set_event_handler([&](const ed2k::session::SessionEvent& ev){
    if(auto* e = std::get_if<ed2k::session::ServerStateEvent>(&ev)) events.push_back(*e);
  });
  const auto target_ip = IPv4::from_dotted("127.0.0.1").value();
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await session.connect_server(ed2k::app::ServerTarget{target_ip, srv.port()});
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;                     // 协程体内禁用 ASSERT_*; 失败时守卫式提前返回
    // 方案 C: SERVERIDENT 已在 connect_server 的初始快照窗口内同步处理完毕, 无需额外等待。
    co_return;
  });
  ASSERT_EQ(events.size(), 2u);           // connect 时的初始占位事件 + ident 更新后的事件
  EXPECT_TRUE(events.front().connected);
  EXPECT_EQ(events.front().ip, target_ip);          // 初始事件仍是占位的 target 地址
  const auto& last = events.back();
  EXPECT_TRUE(last.connected);
  EXPECT_EQ(last.ip, ident_ip);            // 修复前: 停留在 target_ip, 不会被 ident 覆盖
  EXPECT_EQ(last.port, ident_port);
  EXPECT_EQ(last.name, ident_name);
  std::filesystem::remove_all(tmp_dir);
}

// search() 前置条件: 必须已 connect_server, 否则直接返回 errc::connect_failed, 不发任何请求。
TEST(SessionSearch, NotConnectedReturnsError){
  IoRuntime rt;
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_search_noconn_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg; cfg.data_dir = tmp_dir;
  Session session(rt, cfg);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await session.search("foo", {});
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::connect_failed));
    co_return;
  });
  std::filesystem::remove_all(tmp_dir);
}

// connect_server 成功后 search() 转发 SEARCHREQUEST 并解析 mock 应答的 SEARCHRESULT;
// SEARCHRESULT 载荷构造逐字复用 tests/server_connection_test.cpp 中 ServerConnection.SearchRoundTrip
// 用例的写法(count=1 + hash16 + client_id + port + tag_count), 额外补一个 FT_FILESIZE tag 以便断言 size。
TEST(SessionSearch, ReturnsFilteredResults){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    (void)co_await read_frame(s);   // SEARCHREQUEST
    { codec::ByteWriter w; w.u32(1);
      auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
      w.hash16(h); w.u32(0xDDCCBBAAu); w.u16(0x1234u); w.u32(2);
      w.u8(0x82); w.u8(ed2k::server::tag::FT_FILENAME); w.string16("plain");
      w.u8(0x83); w.u8(ed2k::server::tag::FT_FILESIZE); w.u32(123456u);
      co_await send_pkt(s, ed2k::server::op::SEARCHRESULT, w.take());
    }
    co_await keep_alive(s);
    co_return;
  });
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_search_test";
  std::filesystem::create_directories(tmp_dir);
  // 方案 C: mock 在 IDCHANGE 后不发任何快照推送(直接等 SEARCHREQUEST), connect_server 的初始
  // 快照窗口会读满 per_server_timeout 才结束; 设小一些让测试快速跑完, 不影响 search() 本身的
  // 独占读取(窗口结束后连接已空闲, search() 按需单独占用, 无并发)。
  SessionConfig cfg; cfg.data_dir = tmp_dir; cfg.per_server_timeout = 100ms;
  Session session(rt, cfg);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto lr = co_await session.connect_server(
      ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()});
    EXPECT_TRUE(lr.has_value()) << (lr? "" : lr.error().message());
    if(!lr) co_return;                    // 协程体内禁用 ASSERT_*; 失败时守卫式提前返回
    ed2k::session::SearchFilters filters;
    filters.min_size = 100;               // 触发 SizeAtLeast 组合分支
    auto r = co_await session.search("foo", filters);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;
    EXPECT_EQ(r->size(), 1u);
    if(r->size()!=1u) co_return;
    EXPECT_EQ((*r)[0].name, "plain");
    EXPECT_EQ((*r)[0].size, 123456u);
    co_return;
  });
  std::filesystem::remove_all(tmp_dir);
}

// 搜索结果的源数/完整源数应从 FT_SOURCES(0x15)/FT_COMPLETE_SOURCES(0x30) tag 直读为字段
TEST(SessionSearch, ExtractsSourcesAndCompleteSources){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    (void)co_await read_frame(s);   // SEARCHREQUEST
    { codec::ByteWriter w; w.u32(1);
      auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
      w.hash16(h); w.u32(0xDDCCBBAAu); w.u16(0x1234u); w.u32(4);
      w.u8(0x82); w.u8(ed2k::server::tag::FT_FILENAME); w.string16("plain");
      w.u8(0x83); w.u8(ed2k::server::tag::FT_FILESIZE); w.u32(123456u);
      w.u8(0x83); w.u8(ed2k::server::tag::FT_SOURCES); w.u32(56u);
      w.u8(0x83); w.u8(ed2k::server::tag::FT_COMPLETE_SOURCES); w.u32(41u);
      co_await send_pkt(s, ed2k::server::op::SEARCHRESULT, w.take());
    }
    co_await keep_alive(s);
    co_return;
  });
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_srcs_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg; cfg.data_dir = tmp_dir; cfg.per_server_timeout = 100ms;
  Session session(rt, cfg);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto lr = co_await session.connect_server(
      ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()});
    EXPECT_TRUE(lr.has_value());
    if(!lr) co_return;
    auto r = co_await session.search("foo", {});
    EXPECT_TRUE(r.has_value());
    if(!r || r->size()!=1u) co_return;
    EXPECT_EQ((*r)[0].sources, 56u);
    EXPECT_EQ((*r)[0].complete_sources, 41u);
    co_return;
  });
  std::filesystem::remove_all(tmp_dir);
}

// UAF 回归: connect_server()/search() 跨多次 co_await 访问 Impl 必须走 weak_ptr(与
// run_task/sampler 同构), 而不是隐式捕获 this——否则 Session 在协程挂起期间被销毁(如调用方
// quit/切账号)会导致挂起协程恢复后访问已悬垂的 this->impl_。
// 构造确定性场景: mock server 在 login 后立即回一个最小 SERVERIDENT(让 connect_server 的初始
// 快照窗口秒结束, 不必等满 2s 上限), 随后读到 SEARCHREQUEST 后故意不回复(让 search() 底层
// conn.recv() 一直挂起等待响应)。另起一个协程在明显早于 search() 自身 per_server_timeout(特意
// 设得很长, 5s)的时间点(300ms)主动销毁 Session——其析构会 close() 掉同一条连接, 促使 search()
// 挂起的 recv() 在下一个 io_context tick 以错误唤醒。断言: 进程不崩溃(UAF 会在此处崩溃或数据
// 损坏)、search 协程能安全收尾并返回错误(而非死等或崩溃)。
TEST(SessionSearch, SearchSurvivesSessionDestructionWhileAwaitingReply){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
      co_await send_pkt(s, ed2k::server::op::IDCHANGE, w.take()); }
    { codec::ByteWriter w;   // 立即发最小 SERVERIDENT(0 个 tag), 让快照窗口尽快结束
      w.hash16(MD4Hash{});
      w.u32_be(IPv4::from_dotted("127.0.0.1").value().host());
      w.u16(0);
      w.u32(0);
      co_await send_pkt(s, ed2k::server::op::SERVERIDENT, w.take());
    }
    (void)co_await read_frame(s);   // SEARCHREQUEST — 故意不回复, 让 search() 的 recv 一直挂起
    co_await keep_alive(s);         // 保持连接打开, 直到客户端 close(Session 析构触发)
    co_return;
  });
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_search_uaf_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg; cfg.data_dir = tmp_dir;
  cfg.per_server_timeout = 5000ms;   // 远大于下面销毁 Session 前的等待时长, 确保销毁时 search 仍挂起中
  std::optional<Session> session;
  session.emplace(rt, cfg);
  bool search_completed = false;
  bool search_had_error = false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
    auto lr = co_await session->connect_server(
      ed2k::app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()});
    if(!lr){ search_completed = true; co_return; }   // 守卫: 不应发生, 连接失败就不必继续
    auto r = co_await session->search("foo", {});
    // 走到这里说明 search() 协程即便在 Session 已被销毁的情况下也安全收尾(没有 UAF 崩溃)。
    search_completed = true;
    search_had_error = !r.has_value();
    co_return;
  }, asio::detached);
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
    asio::steady_timer timer(rt.context());
    // 300ms 远小于 per_server_timeout(5s), 留足时间让上面的协程已发出 SEARCHREQUEST 并挂起在
    // 等待响应的 recv() 上, 确保下面的销毁确实落在"协程挂起期间", 而不是抢在其发起请求之前。
    timer.expires_after(300ms);
    co_await timer.async_wait(asio::use_awaitable);
    session.reset();                // 触发 ~Session -> shutdown() -> conn.close()
    co_return;
  }, asio::detached);
  rt.run(); rt.restart();
  EXPECT_TRUE(search_completed);
  EXPECT_TRUE(search_had_error);    // 连接被关闭, search 应以错误收尾, 而非死等或崩溃
  std::filesystem::remove_all(tmp_dir);
}
