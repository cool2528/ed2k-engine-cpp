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

TEST(Connection, RecvTimesOut){
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    std::array<std::byte,5> hdr;                 // 等客户端发数据，但客户端不发 → 直到 close 才 eof
    auto [e,n] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
    (void)e; (void)n; co_return;
  });
  std::uint16_t port = peer.port();
  run_coro(rt, [&]() -> asio::awaitable<void>{
    Connection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), port, std::chrono::seconds(2));
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto rr = co_await c.recv(std::chrono::milliseconds(100));
    EXPECT_FALSE(rr.has_value());
    if(!rr) EXPECT_EQ(rr.error(), make_error_code(errc::timed_out));
    c.close();
    co_return;
  });
}

TEST(Connection, RecvOnPeerCloseFails){
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    boost::system::error_code ig; s.close(ig); co_return;          // 立刻关闭
  });
  std::uint16_t port = peer.port();
  run_coro(rt, [&]() -> asio::awaitable<void>{
    Connection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), port, std::chrono::seconds(2));
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto rr = co_await c.recv(std::chrono::seconds(2));
    EXPECT_FALSE(rr.has_value());
    if(!rr) EXPECT_EQ(rr.error(), make_error_code(errc::connection_closed));
    c.close();
    co_return;
  });
}

TEST(Connection, ConnectToDeadPortFails){
  IoRuntime rt;
  std::uint16_t dead;
  { tcp::acceptor a(rt.context(), tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
    dead = a.local_endpoint().port(); boost::system::error_code ig; a.close(ig); }
  run_coro(rt, [&]() -> asio::awaitable<void>{
    Connection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), dead, std::chrono::milliseconds(500));
    EXPECT_FALSE(cr.has_value());        // 无论 OS 是 RST 拒绝还是丢包超时，都不应成功
    if(!cr) EXPECT_TRUE(cr.error()==make_error_code(errc::connect_failed) ||
                        cr.error()==make_error_code(errc::timed_out));
    co_return;
  });
}

TEST(Connection, OversizeHeaderRejected){
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    std::array<std::byte,5> hdr{ std::byte{0xE3}, std::byte{0xFF},std::byte{0xFF},std::byte{0xFF},std::byte{0xFF} };
    auto [e1,n1] = co_await asio::async_write(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
    if(e1) co_return;
    std::array<std::byte,1> tmp;                                   // 保持连接直到客户端关闭
    auto [e2,n2] = co_await asio::async_read(s, asio::buffer(tmp), asio::as_tuple(asio::use_awaitable));
    (void)e2; (void)n2; co_return;
  });
  std::uint16_t port = peer.port();
  run_coro(rt, [&]() -> asio::awaitable<void>{
    Connection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), port, std::chrono::seconds(2));
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto rr = co_await c.recv(std::chrono::seconds(2));
    EXPECT_FALSE(rr.has_value());
    if(!rr) EXPECT_EQ(rr.error(), make_error_code(errc::packet_too_large));
    c.close();
    co_return;
  });
}

TEST(Connection, TruncatedBodyOnCloseFails){
  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    Packet p; p.protocol=proto::eMule; p.opcode=0x01; p.payload.resize(64, std::byte{0});
    auto full = encode_frame(p);
    auto [e,n] = co_await asio::async_write(s, asio::buffer(full.data(), 8),  // 只发 8 字节（头全+部分体）
                                            asio::as_tuple(asio::use_awaitable));
    if(e) co_return;
    boost::system::error_code ig; s.close(ig);                    // 中途关闭
    co_return;
  });
  std::uint16_t port = peer.port();
  run_coro(rt, [&]() -> asio::awaitable<void>{
    Connection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), port, std::chrono::seconds(2));
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto rr = co_await c.recv(std::chrono::seconds(2));
    EXPECT_FALSE(rr.has_value());                                 // 体读到一半 eof → connection_closed
    if(!rr) EXPECT_EQ(rr.error(), make_error_code(errc::connection_closed));
    c.close();
    co_return;
  });
}
