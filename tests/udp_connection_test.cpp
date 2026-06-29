#include <gtest/gtest.h>
#include <chrono>
#include <exception>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include "ed2k/server/udp_connection.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/server/udp_messages.hpp"
#include "ed2k/server/search_query.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"
#include "mock_udp_server.hpp"
using namespace ed2k; using namespace ed2k::server; using namespace ed2k::net;
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
static std::vector<std::byte> search_item(std::string_view name){
  codec::ByteWriter w;
  auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  w.hash16(h); w.u32(0xDDCCBBAAu); w.u16(0x1234u); w.u32(1);
  w.u8(0x82); w.u8(tag::FT_FILENAME); w.string16(name);
  return w.take();
}
TEST(UdpConnection, GlobalSearchRoundTrip){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    co_await ed2k::test::send_packet_to(s, from, udpop::GLOBSEARCHRES, search_item("found"));
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.global_search(Keyword{"foo"}, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->items.size(), 1u); if(r->items.size() != 1u) co_return;
    EXPECT_EQ(r->items[0].name, "found");
    c.close(); co_return;
  });
}
TEST(UdpConnection, GlobalSearchZlibInflated){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    co_await ed2k::test::send_zlib_packet_to(s, from, udpop::GLOBSEARCHRES, search_item("zlib"));
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.global_search(Keyword{"foo"}, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->items.size(), 1u); if(r->items.size() != 1u) co_return;
    EXPECT_EQ(r->items[0].name, "zlib");        // P2/udp_framing 透明解压 0xD4
    c.close(); co_return;
  });
}
TEST(UdpConnection, GetSourcesRoundTrip){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter w;
    auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
    w.hash16(h); w.u8(2);
    w.u32(0x01000000u); w.u16(0x1234u);          // HighID
    w.u32(5u); w.u16(0x5678u);                   // LowID
    co_await ed2k::test::send_packet_to(s, from, udpop::GLOBFOUNDSOURCES, w.take());
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
    auto r = co_await c.get_sources(h, 100, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->sources.size(), 2u); if(r->sources.size() != 2u) co_return;
    EXPECT_FALSE(r->sources[0].low_id());
    EXPECT_TRUE(r->sources[1].low_id());
    c.close(); co_return;
  });
}
