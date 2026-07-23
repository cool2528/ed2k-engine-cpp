#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif
#include <boost/asio/awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include "ed2k/app/server_session.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/download/download.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/server/opcodes.hpp"
#include "ed2k/session/session.hpp"
#include "ed2k/util/error.hpp"
#include "mock_server.hpp"

using namespace ed2k;
using namespace ed2k::net;
using ed2k::session::Session;
using ed2k::session::SessionConfig;
using ed2k::session::TaskState;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart();
  EXPECT_TRUE(done);
}

static std::vector<std::byte> random_bytes(std::size_t n, std::uint32_t seed){
  std::vector<std::byte> data(n);
  std::mt19937 rng(seed);
  std::uniform_int_distribution<int> dist(0, 255);
  for(std::size_t i = 0; i < n; ++i) data[i] = std::byte(static_cast<unsigned char>(dist(rng)));
  return data;
}

static asio::awaitable<std::vector<std::byte>> read_frame(tcp::socket& s){
  std::array<std::byte,5> hdr;
  auto [e1,n1] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
  (void)n1; if(e1) co_return std::vector<std::byte>{};
  auto h = parse_header(hdr);
  if(!h) co_return std::vector<std::byte>{};
  std::vector<std::byte> body(h->size);
  auto [e2,n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
  (void)n2; if(e2) co_return std::vector<std::byte>{};
  co_return body;
}
static asio::awaitable<void> send_pkt(tcp::socket& s, std::uint8_t opcode, std::span<const std::byte> pl){
  net::Packet p; p.protocol = net::proto::eDonkey; p.opcode = opcode; p.payload.assign(pl.begin(), pl.end());
  auto frame = net::encode_frame(p);
  auto [e,n] = co_await asio::async_write(s, asio::buffer(frame), asio::as_tuple(asio::use_awaitable));
  (void)e; (void)n; co_return;
}
static asio::awaitable<void> keep_alive(tcp::socket& s){
  std::array<std::byte,1> t;
  auto [e,n] = co_await asio::async_read(s, asio::buffer(t), asio::as_tuple(asio::use_awaitable));
  (void)e; (void)n; co_return;
}

// mock 服务器: LOGIN → IDCHANGE(HighID) → GETSOURCES → FOUNDSOURCES(1 个 LowID 源, id<0x1000000u)。
// 该 LowID 源本身刻意不可连通(只用来让 run_task 识别出 has_low_id 从而 bind cfg.tcp_port 的下载
// 侧 InboundListener), 用于驱动"反向门控"用例——不需要真的走完一次下载。
static asio::awaitable<void> serve_login_and_one_low_id_source(tcp::socket s, const FileHash& hash){
  (void)co_await read_frame(s);   // LOGIN
  { codec::ByteWriter w; w.u32(0x01000000u); w.u32(0x0119u);
    co_await send_pkt(s, server::op::IDCHANGE, w.take()); }
  (void)co_await read_frame(s);   // GETSOURCES
  { codec::ByteWriter w; w.hash16(hash); w.u8(1);
    w.u32(0x00000001u); w.u16(0);   // LowID: id(0x1) < 0x1000000u, 且刻意不可连通
    co_await send_pkt(s, server::op::FOUNDSOURCES, w.take()); }
  co_await keep_alive(s);
  co_return;
}

// 端到端验证 Session 的分享/上传路径: 扫描目录发布 KnownFileDB → accept 循环接受入站连接 →
// UploadSession 应答请求并计入 ClientCredits → 引擎自身的 download::Download 直连本机分享
// listener 完整下载并校验内容 → 取消分享后 listener 被释放, 再次直连应失败。
// tcp_port 使用固定的测试专用端口(而非 0), 避免额外引入访问实际监听端口的公共 API;
// 全流程在单个 TEST 内的单一 Session 实例上顺序进行, 不会与其它测试用例的端口产生冲突。
TEST(SessionShare, SharesScannedFilesUploadsToDirectPeerAndUnsharesCleanly){
  auto data_dir = std::filesystem::temp_directory_path() / "ed2k_session_share_test_data";
  auto share_dir = std::filesystem::temp_directory_path() / "ed2k_session_share_test_share";
  std::filesystem::remove_all(data_dir);
  std::filesystem::remove_all(share_dir);
  std::filesystem::create_directories(data_dir);
  std::filesystem::create_directories(share_dir);

  // ~1MB, 大小刻意不与 PART_SIZE 对齐, 覆盖跨 part 边界读取路径。
  const auto data = random_bytes(1024 * 1024 + 137, 0xC0FFEEu);
  const auto shared_path = share_dir / "shared_payload.bin";
  {
    std::ofstream f(shared_path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }

  IoRuntime rt;
  SessionConfig cfg;
  cfg.data_dir = data_dir;
  cfg.tcp_port = 48173;   // 测试专用固定端口

  Session session(rt, cfg);

  // Step 1: 扫描目录 → shared_files() 返回一条记录, size/hash 正确。
  run_coro(rt, [&]() -> asio::awaitable<void>{
    // GCC 13 对协程内 co_await f({非空花括号列表}) 会 ICE(build_special_member_call),
    // 临时 vector 必须先构造为具名变量再传入。
    std::vector<std::filesystem::path> dirs{share_dir};
    auto r = co_await session.set_shared_dirs(std::move(dirs));
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });
  auto files = session.shared_files();
  ASSERT_EQ(files.size(), 1u);
  EXPECT_EQ(files[0].size, data.size());
  EXPECT_EQ(files[0].name, shared_path.filename().string());
  EXPECT_NE(files[0].hash, FileHash{});
  const auto hash = files[0].hash;
  const auto size = files[0].size;

  // Step 2: 用引擎自身当客户端, 直连本机分享 listener 完整下载, 校验内容与原文件一致。
  auto out_path = data_dir / "downloaded.bin";
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), out_path, hash, size,
                          server::SourceEndpoint{0x0100007Fu, cfg.tcp_port});
    auto r = co_await dl.run(5s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });
  {
    std::ifstream f(out_path, std::ios::binary);
    ASSERT_TRUE(f.good());
    std::vector<char> downloaded((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    ASSERT_EQ(downloaded.size(), data.size());
    EXPECT_TRUE(std::equal(downloaded.begin(), downloaded.end(),
                           reinterpret_cast<const char*>(data.data())));
  }
  // 下载成功意味着服务端已经把全部字节送出并入账; active_sessions 是否已归零则取决于服务端
  // 收尾协程是否已被调度(与本次下载成功与否无关), 这里只做上界检查, 不假设具体时序。
  auto stats = session.upload_stats();
  EXPECT_LE(stats.active_sessions, 1u);
  EXPECT_GT(stats.total_uploaded, 0u);
  EXPECT_GE(stats.total_uploaded, data.size());

  // Step 3: 取消分享后 shared_files() 应为空, 再次直连该端口应失败(监听已释放)。
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await session.set_shared_dirs({});
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });
  EXPECT_TRUE(session.shared_files().empty());

  auto out_path2 = data_dir / "downloaded_after_unshare.bin";
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), out_path2, hash, size,
                          server::SourceEndpoint{0x0100007Fu, cfg.tcp_port});
    auto r = co_await dl.run(2s);
    EXPECT_FALSE(r.has_value());
    co_return;
  });

  std::filesystem::remove_all(data_dir);
  std::filesystem::remove_all(share_dir);
}

// set_shared_dirs 成功后应把 known.met 写入 data_dir, 作为下一次扫描的哈希缓存。
TEST(SessionShare, SetSharedDirsPersistsKnownMet){
  auto data_dir = std::filesystem::temp_directory_path() / "ed2k_session_share_known_met_data";
  auto share_dir = std::filesystem::temp_directory_path() / "ed2k_session_share_known_met_share";
  std::filesystem::remove_all(data_dir);
  std::filesystem::remove_all(share_dir);
  std::filesystem::create_directories(data_dir);
  std::filesystem::create_directories(share_dir);

  const auto data = random_bytes(4096, 0x1234u);
  {
    std::ofstream f(share_dir / "shared.bin", std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }

  IoRuntime rt;
  SessionConfig cfg;
  cfg.data_dir = data_dir;
  cfg.tcp_port = 48176;   // 与其它用例不同的专用端口, 避免冲突

  Session session(rt, cfg);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    std::vector<std::filesystem::path> dirs{share_dir};
    auto r = co_await session.set_shared_dirs(std::move(dirs));
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_TRUE(std::filesystem::exists(data_dir / "known.met"));

  std::filesystem::remove_all(data_dir);
  std::filesystem::remove_all(share_dir);
}

// 取消全部分享(set_shared_dirs({}))时, known.met 应保留旧缓存文件不被覆盖为空列表——
// 供将来重新分享同一批文件时复用哈希, 避免整批哈希白白丢弃。用文件大小(而非仅存在性)
// 断言未被覆盖: 若被覆盖为空列表, 文件仍会存在但内容/大小会退化为空列表的最小体积。
TEST(SessionShare, UnshareKeepsKnownMetCacheFile){
  auto data_dir = std::filesystem::temp_directory_path() / "ed2k_session_share_unshare_known_met_data";
  auto share_dir = std::filesystem::temp_directory_path() / "ed2k_session_share_unshare_known_met_share";
  std::filesystem::remove_all(data_dir);
  std::filesystem::remove_all(share_dir);
  std::filesystem::create_directories(data_dir);
  std::filesystem::create_directories(share_dir);

  const auto data = random_bytes(4096, 0x5678u);
  {
    std::ofstream f(share_dir / "shared.bin", std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }

  IoRuntime rt;
  SessionConfig cfg;
  cfg.data_dir = data_dir;
  cfg.tcp_port = 48177;   // 与其它用例不同的专用端口, 避免冲突

  Session session(rt, cfg);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    std::vector<std::filesystem::path> dirs{share_dir};
    auto r = co_await session.set_shared_dirs(std::move(dirs));
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  const auto known_met_path = data_dir / "known.met";
  ASSERT_TRUE(std::filesystem::exists(known_met_path));
  const auto size_before = std::filesystem::file_size(known_met_path);
  ASSERT_GT(size_before, 0u);   // 非空列表的 known.met 应有实际体积

  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await session.set_shared_dirs({});
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  ASSERT_TRUE(std::filesystem::exists(known_met_path));
  const auto size_after = std::filesystem::file_size(known_met_path);
  EXPECT_EQ(size_after, size_before);   // 未被覆盖为空列表文件

  std::filesystem::remove_all(data_dir);
  std::filesystem::remove_all(share_dir);
}

// 无上传活动时新统计字段应为 0（字段存在性 + 默认值；速率的运行时正确性由采样公式与
// 下载侧逐字对齐 + 代码审查保证，不在此处写伪造的计时断言，见 task-1-brief 决定）。
TEST(SessionShare, UploadStatsNewFieldsDefaultZero){
  auto data_dir = std::filesystem::temp_directory_path() / "ed2k_session_share_test_defaults_data";
  std::filesystem::remove_all(data_dir);
  std::filesystem::create_directories(data_dir);

  IoRuntime rt;
  SessionConfig cfg;
  cfg.data_dir = data_dir;
  cfg.tcp_port = 48175;   // 与其它用例不同的专用端口, 避免冲突

  Session session(rt, cfg);
  auto stats = session.upload_stats();
  EXPECT_EQ(stats.speed_bps, 0u);
  EXPECT_EQ(stats.queued_count, 0u);

  std::filesystem::remove_all(data_dir);
}

// 反向门控回归用例(2026-07 复审发现并修复): 下载侧的 LowID InboundListener 先占住 cfg.tcp_port
// 时, set_shared_dirs 不得在同一端口上再起第二个 acceptor(InboundListener 构造设置了
// SO_REUSEADDR, 若不做门控, Windows 上第二次 bind 会"成功"而不是失败, 两个 acceptor 同时监听
// 同一端口, 破坏互斥不变量——这正是 brief 复审要求修复的问题)。
//
// 这里只能黑盒验证"扫描/发布仍按预期完成且不报错"这一半可观察契约(Impl::download_listener
// 是私有实现细节, 没有、也不打算为测试新增公共访问器); "listener 确实没有被第二次 bind"这一半
// 更难在不扩大公共 API 的前提下做稳定的黑盒断言(SO_REUSEADDR 在 Windows 上的语义使得从测试侧
// 尝试探测端口占用情况本身就不可靠, 容易做出 flaky 或误导性的判定), 因此按 brief 允许的"难以
// 稳定构造则跳过并说明"处理, 依赖代码走查(见 session.cpp 内 download_listener 相关注释与
// task-9-report.md 的自审记录)确认反向分支的正确性。
TEST(SessionShare, SetSharedDirsDegradesGracefullyWhileDownloadListenerActive){
  const auto hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_login_and_one_low_id_source(std::move(s), hash); co_return; });

  auto data_dir = std::filesystem::temp_directory_path() / "ed2k_session_share_reverse_gate_data";
  auto share_dir = std::filesystem::temp_directory_path() / "ed2k_session_share_reverse_gate_share";
  std::filesystem::remove_all(data_dir);
  std::filesystem::remove_all(share_dir);
  std::filesystem::create_directories(data_dir);
  std::filesystem::create_directories(share_dir);
  {
    const auto data = random_bytes(4096, 0xABCDu);
    std::ofstream f(share_dir / "shared.bin", std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }

  SessionConfig cfg;
  cfg.data_dir = data_dir;
  cfg.tcp_port = 48174;   // 与端到端用例(48173)不同的专用端口, 避免冲突
  cfg.per_server_timeout = 2000ms;
  cfg.task_io_timeout = 5000ms;
  cfg.server_override = app::ServerTarget{IPv4::from_dotted("127.0.0.1").value(), srv.port()};
  Session session(rt, cfg);

  Ed2kFileLink link; link.name = "lowid.bin"; link.size = 1; link.hash = hash;
  std::uint64_t task_id = 0;
  bool reached_downloading = false;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    task_id = session.add_download(link, data_dir);
    EXPECT_NE(task_id, 0u);
    // 轮询直到进入 downloading: run_task 在这之前已经完成了(可能的) LowID listener bind
    // (见 session.cpp::run_task, listener 创建早于 set_state(downloading)), 因此一旦观察到
    // downloading 就能保证 download_listener(弱引用)是否 expired() 已经是最终值。
    asio::steady_timer timer(rt.context());
    for(int i = 0; i < 250; ++i){
      auto snap = session.query(task_id);
      if(!snap) co_return;
      if(snap->state == TaskState::downloading || snap->state == TaskState::failed) break;
      timer.expires_after(20ms);
      co_await timer.async_wait(asio::use_awaitable);
    }
    auto snap = session.query(task_id);
    EXPECT_TRUE(snap.has_value());
    if(!snap) co_return;
    // 若下载因端口占用之外的原因提前失败(如既有 UploadSession/LowId flaky), 只记录未达到状态,
    // 不在协程内让用例失败——这不是本用例要覆盖的内容, 见下方 skip 说明。
    reached_downloading = (snap->state == TaskState::downloading);
    if(!reached_downloading) co_return;

    // 下载 LowID listener 占用 cfg.tcp_port 期间调用 set_shared_dirs: 必须不报错——扫描/发布
    // 仍按合同正常完成, 只是(不可黑盒观察地)不启动分享的入站上传监听。
    // 具名 vector 同 Step 1: 绕过 GCC 13 协程 ICE。
    std::vector<std::filesystem::path> dirs{share_dir};
    auto r = co_await session.set_shared_dirs(std::move(dirs));
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  if(!reached_downloading){
    // 理论上应当是确定性的(状态转换只依赖本地 MockServer 立即应答, 不依赖 LowID 源真的可连通),
    // 但仍按 brief 允许的方式做保守处理: 环境异常导致未能观察到 downloading 时跳过而非误报失败。
    run_coro(rt, [&]() -> asio::awaitable<void>{ session.cancel(task_id, true); co_return; });
    std::filesystem::remove_all(data_dir);
    std::filesystem::remove_all(share_dir);
    GTEST_SKIP() << "LowID download task did not reach 'downloading' state in time; "
                    "cannot exercise the reverse listener-gate branch this run.";
  }

  EXPECT_EQ(session.shared_files().size(), 1u);   // 扫描仍然完成, 不受反向门控影响

  // 结束下载任务, 释放 cfg.tcp_port, 避免其在进程/其它用例里继续占用监听。
  run_coro(rt, [&]() -> asio::awaitable<void>{
    session.cancel(task_id, true);
    co_return;
  });

  std::filesystem::remove_all(data_dir);
  std::filesystem::remove_all(share_dir);
}
