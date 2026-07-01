#include <gtest/gtest.h>
#include <chrono>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/net/runtime.hpp"
#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/util/error.hpp"
using namespace ed2k; using namespace ed2k::peer;
namespace asio = boost::asio; using tcp = asio::ip::tcp;
using namespace std::chrono_literals;
template <class F> static void run_coro(ed2k::net::IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}
TEST(InboundListener, AcceptsInboundConnection){
  ed2k::net::IoRuntime rt;
  InboundListener lst(rt.executor(), 0);   // ephemeral port
  EXPECT_NE(lst.local_port(), 0u);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    // 同时发起 accept 与一个出站连接
    tcp::socket client(rt.executor());
    tcp::endpoint ep(asio::ip::make_address_v4("127.0.0.1"), lst.local_port());
    auto [ec] = co_await client.async_connect(ep, asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec);
    auto acc = co_await lst.accept(2000ms);
    EXPECT_TRUE(acc.has_value()) << (acc? "" : acc.error().message());
    if(!acc) co_return;
    EXPECT_TRUE(acc->is_open());
    // 回声验证: client 写一字节, accept 侧读到
    std::byte out{0xAB};
    auto [we,wn] = co_await asio::async_write(client, asio::buffer(&out,1), asio::as_tuple(asio::use_awaitable));(void)we;(void)wn;
    std::byte in{};
    auto [re,rn] = co_await asio::async_read(*acc, asio::buffer(&in,1), asio::as_tuple(asio::use_awaitable));(void)re;(void)rn;
    EXPECT_EQ(in, std::byte(0xAB));
    co_return;
  });
}
TEST(InboundListener, AcceptTimesOut){
  ed2k::net::IoRuntime rt;
  InboundListener lst(rt.executor(), 0);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto acc = co_await lst.accept(200ms);
    EXPECT_FALSE(acc.has_value());
    if(!acc) EXPECT_EQ(acc.error(), make_error_code(errc::timed_out));
    co_return;
  });
}
