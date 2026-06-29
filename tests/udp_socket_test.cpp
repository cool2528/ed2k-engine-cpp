#include <gtest/gtest.h>
#include <chrono>
#include <exception>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include "ed2k/net/udp_socket.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/util/error.hpp"
using namespace ed2k; using namespace ed2k::net;
namespace asio = boost::asio;
using udp = asio::ip::udp;
using namespace std::chrono_literals;
template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(),
    [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart();
  EXPECT_TRUE(done);
}
TEST(UdpSocket, SendRecvRoundTrip){
  IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpSocket a(rt.executor()), b(rt.executor());
    Packet p; p.protocol=proto::eDonkey; p.opcode=0x92; p.payload={std::byte{1},std::byte{2}};
    auto sr = co_await a.send_to(udp::endpoint(asio::ip::address_v4::loopback(), b.local_endpoint().port()), p);
    EXPECT_TRUE(sr.has_value()); if(!sr) co_return;
    auto rr = co_await b.recv_from(2s);
    EXPECT_TRUE(rr.has_value()); if(!rr) co_return;
    EXPECT_EQ(rr->first.opcode, 0x92);
    EXPECT_EQ(rr->first.payload, p.payload);
    a.close(); b.close(); co_return;
  });
}
TEST(UdpSocket, RecvTimesOut){
  IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpSocket s(rt.executor());
    auto rr = co_await s.recv_from(100ms);
    EXPECT_FALSE(rr.has_value());
    if(!rr) EXPECT_EQ(rr.error(), make_error_code(errc::timed_out));
    s.close(); co_return;
  });
}
