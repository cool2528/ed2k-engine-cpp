#include <gtest/gtest.h>
#include <array>
#include <chrono>
#include <exception>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/net/connection.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/util/error.hpp"
#include "mock_peer.hpp"
using namespace ed2k; using namespace ed2k::net;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// 把测试协程跑到完成；完成即 stop() 让 peer 的挂起操作收场；异常上抛为测试失败。
// 注意：协程体内只能用 EXPECT_*，不能用 ASSERT_*（其 return; 在协程里非法）。
template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(),
    [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart();
  EXPECT_TRUE(done);
}

TEST(Connection, ConnectSendRecvRoundTrip){
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    std::array<std::byte,5> hdr;
    auto [e1,n1] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
    if(e1) co_return;
    auto h = parse_header(hdr); if(!h) co_return;
    std::vector<std::byte> body(h->size);
    auto [e2,n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
    if(e2) co_return;
    Packet reply; reply.protocol=proto::eMule; reply.opcode=0x42; reply.payload={std::byte{9},std::byte{9}};
    auto out = encode_frame(reply);
    co_await asio::async_write(s, asio::buffer(out), asio::as_tuple(asio::use_awaitable));
    co_return;
  });
  std::uint16_t port = peer.port();
  run_coro(rt, [&]() -> asio::awaitable<void>{
    Connection c(rt.executor());
    auto ip = *IPv4::from_dotted("127.0.0.1");
    auto cr = co_await c.connect(ip, port, std::chrono::seconds(2));
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    Packet req; req.protocol=proto::eMule; req.opcode=0x01; req.payload={std::byte{1}};
    auto sr = co_await c.send(req);
    EXPECT_TRUE(sr.has_value()); if(!sr) co_return;
    auto rr = co_await c.recv(std::chrono::seconds(2));
    EXPECT_TRUE(rr.has_value()); if(!rr) co_return;
    EXPECT_EQ(rr->protocol, proto::eMule);
    EXPECT_EQ(rr->opcode, 0x42);
    EXPECT_EQ(rr->payload.size(), 2u);
    c.close();
    co_return;
  });
}
