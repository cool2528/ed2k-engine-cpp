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
#include "ed2k/net/runtime.hpp"
#include "ed2k/session/session.hpp"
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
