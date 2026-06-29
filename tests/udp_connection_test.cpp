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
TEST(UdpConnection, GetSourcesNoMatchReturnsEmpty){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter w;
    auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");  // 服务端回的是另一个 hash
    w.hash16(h); w.u8(2);
    w.u32(0x01000000u); w.u16(0x1234u);          // HighID
    w.u32(5u); w.u16(0x5678u);                   // LowID
    co_await ed2k::test::send_packet_to(s, from, udpop::GLOBFOUNDSOURCES, w.take());
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto h = *FileHash::from_hex("ffeeddccbbaa99887766554433221100");  // 客户端请求的 hash(与 mock 不同)
    auto r = co_await c.get_sources(h, 100, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->hash, h);                        // 不是 mock 的 hash
    EXPECT_TRUE(r->sources.empty());
    c.close(); co_return;
  });
}
TEST(UdpConnection, ServerStatusChallengeOk){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter w; w.u32(0xCAFEBABEu); w.u32(100); w.u32(5000);
    co_await ed2k::test::send_packet_to(s, from, udpop::GLOBSERVSTATRES, w.take());
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.server_status(0xCAFEBABEu, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->users, 100u);
    c.close(); co_return;
  });
}
TEST(UdpConnection, ServerStatusChallengeMismatch){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter w; w.u32(0xCAFEBABEu); w.u32(1); w.u32(2);
    co_await ed2k::test::send_packet_to(s, from, udpop::GLOBSERVSTATRES, w.take());
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.server_status(0xDEADBEEFu, 2s);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::server_protocol_error));
    c.close(); co_return;
  });
}
TEST(UdpConnection, ServerListRoundTrip){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter w; w.u8(1); w.u32(0x01020304u); w.u16(0x1234u);
    co_await ed2k::test::send_packet_to(s, from, udpop::SERVER_LIST_RES, w.take());
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.server_list(IPv4{0x01020304u}, 0x1234u, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->size(), 1u); if(r->size() != 1u) co_return;
    EXPECT_EQ((*r)[0].first.value, 0x01020304u);
    c.close(); co_return;
  });
}
TEST(UdpConnection, ServerDescNewFormat){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter w; w.u32(0x1234F0FFu); w.u32(2);
    w.u8(0x82); w.u8(tag::ST_SERVERNAME);  w.string16("n");
    w.u8(0x82); w.u8(tag::ST_DESCRIPTION); w.string16("d");
    co_await ed2k::test::send_packet_to(s, from, udpop::SERVER_DESC_RES, w.take());
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.server_desc(0x1234F0FFu, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->name, "n");
    EXPECT_EQ(r->description, "d");
    c.close(); co_return;
  });
}
TEST(UdpConnection, ServerDescOldFormat){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter w; w.string16("des"); w.string16("nm");
    co_await ed2k::test::send_packet_to(s, from, udpop::SERVER_DESC_RES, w.take());
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.server_desc(0, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->description, "des");
    EXPECT_EQ(r->name, "nm");
    c.close(); co_return;
  });
}
TEST(UdpConnection, ServerDescChallengeMismatch){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter w; w.u32(0x1234F0FFu); w.u32(2);      // 新格式,challenge 与客户端所发不同
    w.u8(0x82); w.u8(tag::ST_SERVERNAME);  w.string16("n");
    w.u8(0x82); w.u8(tag::ST_DESCRIPTION); w.string16("d");
    co_await ed2k::test::send_packet_to(s, from, udpop::SERVER_DESC_RES, w.take());
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.server_desc(0x9999F0FFu, 2s);       // 客户端发的 challenge(低2字节=0xF0FF,与 mock 不同)
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::server_protocol_error));
    c.close(); co_return;
  });
}
TEST(UdpConnection, InvalidLowIdEmitted){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter w; w.u32(0x00001234u);
    co_await ed2k::test::send_packet_to(s, from, udpop::INVALID_LOWID, w.take());
    co_await ed2k::test::send_packet_to(s, from, udpop::GLOBSEARCHRES, search_item("after"));
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    std::uint32_t got_id = 0;
    c.on_event([&](const UdpEvent& e){ if(std::holds_alternative<InvalidLowIdEvent>(e)) got_id = std::get<InvalidLowIdEvent>(e).id; });
    auto r = co_await c.global_search(Keyword{"foo"}, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(got_id, 0x00001234u);
    c.close(); co_return;
  });
}
TEST(UdpConnection, SearchTimesOut){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket&, const Packet&, const udp::endpoint&) -> asio::awaitable<void>{
    co_return;                                    // 不应答
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.global_search(Keyword{"foo"}, 200ms);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::timed_out));
    c.close(); co_return;
  });
}
