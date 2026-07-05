#include <gtest/gtest.h>

#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "ed2k/infra/statistics.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/util/error.hpp"

using ed2k::infra::Statistics;
namespace asio = boost::asio;
using namespace std::chrono_literals;

namespace {
template <class F>
void run_coro(ed2k::net::IoRuntime& rt, F&& body) {
  bool done = false;
  asio::co_spawn(
      rt.context(),
      [&]() -> asio::awaitable<void> {
        co_await body();
        done = true;
        co_return;
      },
      [&](std::exception_ptr e) {
        rt.stop();
        if (e) {
          std::rethrow_exception(e);
        }
      });
  rt.run();
  rt.restart();
  EXPECT_TRUE(done);
}

std::filesystem::path temp_path(const char* name) {
  return std::filesystem::temp_directory_path() / name;
}
} // namespace

TEST(Statistics, SessionAndCumulativeCountersIncreaseTogether) {
  Statistics stats;
  stats.add_uploaded_bytes(100);
  stats.add_downloaded_bytes(250);
  stats.add_server_connection(true);
  stats.add_server_connection(false);
  stats.add_kad_packet_sent();
  stats.add_source_seen(3);
  stats.add_file_completed();

  const auto session = stats.session();
  const auto cumulative = stats.cumulative();
  EXPECT_EQ(session.uploaded_bytes, 100u);
  EXPECT_EQ(session.downloaded_bytes, 250u);
  EXPECT_EQ(session.server_connections, 2u);
  EXPECT_EQ(session.failed_connections, 1u);
  EXPECT_EQ(session.kad_packets_sent, 1u);
  EXPECT_EQ(session.sources_seen, 3u);
  EXPECT_EQ(session.files_completed, 1u);
  EXPECT_EQ(cumulative, session);
}

TEST(Statistics, PersistenceKeepsCumulativeAndStartsNewSession) {
  Statistics stats;
  stats.add_uploaded_bytes(1000);
  stats.add_downloaded_bytes(2000);
  stats.add_file_completed();

  const auto path = temp_path("ed2k_statistics_roundtrip.dat");
  auto saved = stats.save(path);
  ASSERT_TRUE(saved.has_value()) << saved.error().message();

  auto loaded = Statistics::load(path);
  ASSERT_TRUE(loaded.has_value()) << loaded.error().message();
  EXPECT_EQ(loaded->cumulative().uploaded_bytes, 1000u);
  EXPECT_EQ(loaded->cumulative().downloaded_bytes, 2000u);
  EXPECT_EQ(loaded->cumulative().files_completed, 1u);
  EXPECT_EQ(loaded->session(), ed2k::infra::StatisticsSnapshot{});
  std::filesystem::remove(path);
}

TEST(Statistics, AsyncFlushDoesNotBlockNetworkExecutor) {
  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    Statistics stats;
    stats.add_uploaded_bytes(42);
    const auto path = temp_path("ed2k_statistics_async.dat");
    bool timer_fired = false;

    asio::steady_timer timer(rt.context(), 0ms);
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void> {
      co_await timer.async_wait(asio::use_awaitable);
      timer_fired = true;
      co_return;
    }, asio::detached);

    auto flushed = co_await stats.async_flush(path, rt.disk_executor());
    EXPECT_TRUE(flushed.has_value()) << (flushed ? "" : flushed.error().message());
    EXPECT_TRUE(timer_fired);

    auto loaded = Statistics::load(path);
    EXPECT_TRUE(loaded.has_value()) << (loaded ? "" : loaded.error().message());
    if (loaded) {
      EXPECT_EQ(loaded->cumulative().uploaded_bytes, 42u);
    }
    std::filesystem::remove(path);
    co_return;
  });
}

TEST(Statistics, RejectsBadMagic) {
  const auto path = temp_path("ed2k_statistics_bad.dat");
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << "not stats";
  }

  auto loaded = Statistics::load(path);
  ASSERT_FALSE(loaded.has_value());
  EXPECT_EQ(loaded.error(), ed2k::make_error_code(ed2k::errc::bad_magic));
  std::filesystem::remove(path);
}
