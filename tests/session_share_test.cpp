#include <gtest/gtest.h>
#include <algorithm>
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
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>
#include "ed2k/download/download.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/session/session.hpp"
#include "ed2k/util/error.hpp"

using namespace ed2k;
using namespace ed2k::net;
using ed2k::session::Session;
using ed2k::session::SessionConfig;
namespace asio = boost::asio;
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
    auto r = co_await session.set_shared_dirs({share_dir});
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
