#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <string>
#include <vector>
#include "ed2k/net/runtime.hpp"
#include "ed2k/session/session.hpp"
#include "ed2k/codec/tag.hpp"
#include "ed2k/kad/keywords.hpp"
#include "ed2k/kad/messages.hpp"
#include "ed2k/kad/network.hpp"
#include "ed2k/util/error.hpp"
using namespace ed2k; using namespace ed2k::net;
using ed2k::session::Session;
using ed2k::session::SessionConfig;
namespace asio = boost::asio;
using namespace std::chrono_literals;

template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}

namespace {
// spike 辅助: 从 hex 构造 KadID
kad::KadID kad_kid(const char* hex){ return *kad::KadID::from_hex(hex); }
// spike 辅助: 构造 ephemeral(udp_port=0) 的 KadNetworkOptions, 与 Session::kad_search 里
// 临时查询实例的配置方式一致(自收自响应, 独立 socket)。
kad::KadNetworkOptions kad_opts(const char* id_hex){
  kad::KadNetworkOptions o;
  o.id = kad_kid(id_hex);
  o.ip = *IPv4::from_dotted("127.0.0.1");
  o.udp_port = 0;                 // ephemeral 端口
  o.version = kad::kad2_version;
  return o;
}
// spike 辅助: 构造一条含 filename/file_size 标签的关键词索引条目(照抄 kad_network_test 的 file_entry)
kad::KadSearchEntry kad_file_entry(const char* file_hex, std::string name, std::uint64_t size){
  codec::Tag name_tag;
  name_tag.name_str = std::string(1, static_cast<char>(kad::tag::filename));
  name_tag.value = std::move(name);
  codec::Tag size_tag;
  size_tag.name_str = std::string(1, static_cast<char>(kad::tag::file_size));
  size_tag.value = size;
  return kad::KadSearchEntry{ .answer_id = kad_kid(file_hex), .tags = {std::move(name_tag), std::move(size_tag)} };
}
// spike 辅助: 让 indexer 处理 count 次入站请求(照抄 kad_network_test 的 serve_n)
asio::awaitable<void> kad_serve_n(kad::KadNetwork& network, int count){
  for(int i=0;i<count;++i) (void)co_await network.serve_once(500ms);
  co_return;
}
}  // namespace

// enable_kad=false(默认) 时 Kad 完全不启动: kad_status().running 为 false, contacts 为 0,
// 且不影响既有任务注册表行为(query_all 仍为空)。
TEST(SessionKad, DisabledByDefaultReportsNotRunning){
  IoRuntime rt;
  SessionConfig cfg;
  cfg.data_dir = std::filesystem::temp_directory_path() / "ed2k_session_kad_disabled_test";
  Session session(rt, cfg);
  auto status = session.kad_status();
  EXPECT_FALSE(status.running);
  EXPECT_EQ(status.contacts, 0u);
  EXPECT_TRUE(session.query_all().empty());
}

// enable_kad=true, 但 data_dir 下没有 nodes.dat(首次运行场景): 仍应正常启动
// (kad_status().running==true), bootstrap 因无种子快速失败/超时但不崩溃、不阻塞 Session 可用,
// shutdown() 干净退出(不挂起、不崩溃)。
TEST(SessionKad, EnabledWithMissingNodesDatStartsAndShutsDownCleanly){
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_kad_enabled_test";
  std::filesystem::remove_all(tmp_dir);
  std::filesystem::create_directories(tmp_dir);
  IoRuntime rt;
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.enable_kad = true;
  cfg.kad_udp_port = 0;   // 0 = 系统分配, 避免测试并发跑时端口冲突
  {
    Session session(rt, cfg);
    // 给常驻的 bootstrap+serve_once 协程一个调度窗口(bootstrap 无种子应快速返回)。
    run_coro(rt, [&]() -> asio::awaitable<void>{
      asio::steady_timer timer(rt.context());
      timer.expires_after(100ms);
      co_await timer.async_wait(asio::use_awaitable);
      co_return;
    });
    auto status = session.kad_status();
    EXPECT_TRUE(status.running);
    // 无种子引导, 路由表应为空(不崩溃即可, 不对 contacts 具体值做强断言)。
    EXPECT_EQ(status.contacts, 0u);
  }   // Session 析构 → shutdown(): kad->close() + nodes.dat 落盘, 必须干净退出不挂起/不崩溃
  // shutdown 落盘的 nodes.dat 应该存在(即使联系人为空, write_nodes_dat 也会写出一个有效的空表)。
  EXPECT_TRUE(std::filesystem::exists(tmp_dir / "nodes.dat"));
  std::filesystem::remove_all(tmp_dir);
}

// enable_kad=true 但 kad_udp_port 已被占用(如本机同时跑着真实 eMule/aMule, 或多个 Session
// 实例误配了同一固定端口): KadNetwork 构造函数同步 bind 会抛异常, 修复后应被 Impl 构造函数
// 内的 try/catch 捕获并降级为 kad=nullptr, 而不是让整个 Session 构造函数把异常向上抛出。
TEST(SessionKad, EnabledWithOccupiedPortDegradesGracefully){
  IoRuntime rt;
  // 先用一个独立 UDP socket 占住一个系统分配的端口(不设 SO_REUSEADDR, 默认行为下第二个 bind
  // 到同一端口会失败), 再把这个端口号喂给 enable_kad 的 SessionConfig, 制造端口冲突场景。
  asio::ip::udp::socket occupier(rt.context(), asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
  const auto occupied_port = occupier.local_endpoint().port();

  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_kad_port_conflict_test";
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.enable_kad = true;
  cfg.kad_udp_port = occupied_port;
  Session session(rt, cfg);   // 关键断言: 构造不应抛出(occupier 仍持有该端口)
  auto status = session.kad_status();
  EXPECT_FALSE(status.running);
  EXPECT_EQ(status.contacts, 0u);
}

// Step 1 spike: 验证"临时 ephemeral(udp_port=0)实例能独立完成 keyword 搜索"这一机制成立。
// 这是 Session::kad_search 门面的立身之本——每次搜索都会新建一个 udp_port=0 的临时 KadNetwork,
// 用独立 socket 自收自响应, 从而不与常驻 kad_run 协程争抢主 Kad socket。此处 searcher 用
// ephemeral 端口向 indexer 先 publish 再 search: 若 ephemeral 实例收不到响应(例如响应校验绑定了
// 固定发送端口), publish/search 会失败, 门面方案不成立, 应停止本 Task 并降级为仅服务器搜索。
TEST(SessionKad, EphemeralInstanceCanSearchKeyword){
  IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    // indexer 常驻应答; searcher 为 ephemeral(udp_port=0)客户端。两者均走系统分配端口,
    // searcher 通过 indexer.self_contact()(内部已回填真实绑定端口)定位 indexer。
    const auto key = kad::keyword_id("ubuntu");
    // indexer 的 KadID 落在 key 上: search_keyword 会按 XOR 距离容差(is_within_search_tolerance)
    // 过滤待查询 peer, 只有落在 key 附近的节点才会被真正发起 search_key_req。真实 DHT 中路由表
    // 总能提供靠近任意 key 的节点; 此处单节点测试必须显式把 indexer 放到 key 上以满足该前提,
    // 否则会因容差过滤而收不到结果(与 ephemeral 机制无关)。
    kad::KadNetworkOptions indexer_opts = kad_opts("00000000000000000000000000000002");
    indexer_opts.id = key;
    kad::KadNetwork indexer(rt.executor(), indexer_opts);
    kad::KadNetwork searcher(rt.executor(), kad_opts("00000000000000000000000000000003"));
    const std::vector<kad::KadSearchEntry> files{
        kad_file_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ubuntu.iso", 123456789ull)};

    asio::co_spawn(rt.context(), kad_serve_n(indexer, 8), asio::detached);
    auto publish = co_await searcher.publish_keyword(indexer.self_contact(), key, files, 1s);
    EXPECT_TRUE(publish.has_value());
    if(!publish) co_return;

    std::vector<kad::Contact> peers{ indexer.self_contact() };
    auto results = co_await searcher.search_keyword(peers, key, 1s);
    EXPECT_TRUE(results.has_value());
    if(!results) co_return;
    EXPECT_EQ(results->size(), 1u);
    co_return;
  });
}

// Step 2 (RED): Kad 未启用(enable_kad 默认 false)时 kad_search 应返回 connect_failed。
TEST(SessionKad, KadSearchDisabledReturnsError){
  IoRuntime rt;
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_kadsearch_test";
  std::filesystem::create_directories(tmp_dir);
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;   // enable_kad 默认 false
  Session session(rt, cfg);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await session.kad_search("ubuntu");
    EXPECT_FALSE(r.has_value());
    if(r) co_return;
    EXPECT_EQ(r.error(), make_error_code(ed2k::errc::connect_failed));
    co_return;
  });
  std::filesystem::remove_all(tmp_dir);
}

// enable_kad=true 但路由表为空(无 contacts)时 kad_search 同样返回 connect_failed:
// 没有可查询的 peer, 临时实例无从发起搜索。
TEST(SessionKad, KadSearchEmptyRoutingTableReturnsError){
  auto tmp_dir = std::filesystem::temp_directory_path() / "ed2k_session_kadsearch_empty_test";
  std::filesystem::remove_all(tmp_dir);
  std::filesystem::create_directories(tmp_dir);
  IoRuntime rt;
  SessionConfig cfg;
  cfg.data_dir = tmp_dir;
  cfg.enable_kad = true;
  cfg.kad_udp_port = 0;   // 系统分配, 避免端口冲突
  Session session(rt, cfg);
  ASSERT_TRUE(session.kad_status().running);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto r = co_await session.kad_search("ubuntu");
    EXPECT_FALSE(r.has_value());
    if(r) co_return;
    EXPECT_EQ(r.error(), make_error_code(ed2k::errc::connect_failed));
    co_return;
  });
  std::filesystem::remove_all(tmp_dir);
}
