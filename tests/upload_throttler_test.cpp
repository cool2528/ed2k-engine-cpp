#include <gtest/gtest.h>
#include <chrono>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/steady_timer.hpp>
#include "ed2k/net/runtime.hpp"
#include "ed2k/share/upload_throttler.hpp"

using namespace ed2k::share;
namespace asio = boost::asio;
using namespace std::chrono_literals;

template <class F> static void run_coro(ed2k::net::IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(),
    [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart();
  EXPECT_TRUE(done);
}

TEST(UploadBandwidthThrottler, DelaysBackToBackAcquiresByReservedSendTime){
  ed2k::net::IoRuntime rt;
  UploadBandwidthThrottler throttler(rt.executor(), 1000);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto start = std::chrono::steady_clock::now();
    co_await throttler.acquire(50);
    co_await throttler.acquire(50);
    auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_GE(elapsed, 35ms);
    co_return;
  });
}

TEST(UploadBandwidthThrottler, AcquireDoesNotBlockOtherCoroutines){
  ed2k::net::IoRuntime rt;
  UploadBandwidthThrottler throttler(rt.executor(), 1000);
  bool timer_fired = false;

  run_coro(rt, [&]() -> asio::awaitable<void>{
    co_await throttler.acquire(50);
    asio::steady_timer timer(rt.context());
    timer.expires_after(5ms);
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      co_await timer.async_wait(asio::use_awaitable);
      timer_fired = true;
      co_return;
    }, asio::detached);

    co_await throttler.acquire(50);
    EXPECT_TRUE(timer_fired);
    co_return;
  });
}
