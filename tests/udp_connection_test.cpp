#include <gtest/gtest.h>
#include <array>
#include <chrono>
#include <exception>
#include <span>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include "ed2k/server/udp_connection.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/udp_framing.hpp"
#include "ed2k/net/udp_obfuscation.hpp"
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
TEST(UdpConnection, GetSourcesUsesV2SizeAndAcceptsV2Response){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  std::vector<std::byte> request_payload;
  srv.serve([&](udp::socket& s, const Packet& request, const udp::endpoint& from) -> asio::awaitable<void>{
    EXPECT_EQ(request.opcode, udpop::GLOBGETSOURCES2);
    request_payload = request.payload;
    codec::ByteWriter w;
    w.hash16(h); w.u8(1);
    w.u32(0x01000000u); w.u16(0x1234u);
    co_await ed2k::test::send_packet_to(s, from, udpop::GLOBFOUNDSOURCES2, w.take());
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.get_sources(h, 0x100000001ull, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->sources.size(), 1u);
    EXPECT_EQ(request_payload, encode_get_sources_req(h, 0x100000001ull));
    EXPECT_EQ(request_payload.size(), 24u);
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
TEST(UdpConnection, ServerStatusUsesObfuscatedUdpPortAndDecodesResponse){
  IoRuntime rt;
  udp::socket obfuscated_server(rt.context(), udp::endpoint(asio::ip::address_v4::loopback(), 0));
  const auto obfuscated_port = obfuscated_server.local_endpoint().port();
  const auto udp_key = 0x11223344u;
  bool saw_encrypted_request = false;

  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
    std::array<std::byte, 1024> buffer{};
    udp::endpoint sender;
    auto [ec, n] = co_await obfuscated_server.async_receive_from(
        asio::buffer(buffer), sender, asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec);
    std::span<const std::byte> received{buffer.data(), n};
    EXPECT_NE(received[0], std::byte{proto::eDonkey});

    auto decoded = decode_server_udp_obfuscated_datagram(
        received,
        ServerUdpObfuscationDecodeOptions{
            .base_key = udp_key,
            .direction = ServerUdpObfuscationDirection::client_to_server,
        });
    EXPECT_TRUE(decoded.has_value());
    if(!decoded) co_return;
    saw_encrypted_request = decoded->encrypted;
    auto request = parse_udp_datagram(decoded->datagram);
    EXPECT_TRUE(request.has_value());
    if(!request) co_return;
    EXPECT_EQ(request->opcode, udpop::GLOBSERVSTATREQ);
    EXPECT_EQ(request->payload, encode_server_status_req(0xCAFEBABEu));

    codec::ByteWriter w; w.u32(0xCAFEBABEu); w.u32(100); w.u32(5000);
    Packet response{proto::eDonkey, udpop::GLOBSERVSTATRES, w.take()};
    auto encrypted = encode_server_udp_obfuscated_datagram(
        encode_udp_packet(response),
        ServerUdpObfuscationOptions{
            .base_key = udp_key,
            .direction = ServerUdpObfuscationDirection::server_to_client,
            .random_key_part = 0x2211,
            .marker = 0x24,
        });
    EXPECT_TRUE(encrypted.has_value());
    if(!encrypted) co_return;
    co_await obfuscated_server.async_send_to(asio::buffer(*encrypted), sender,
                                             asio::as_tuple(asio::use_awaitable));
    co_return;
  }, asio::detached);

  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), 9,
                          UdpServerObfuscation{
                              .udp_key = udp_key,
                              .udp_port = obfuscated_port,
                              .random_key_part = 0xbeef,
                              .marker = 0x42,
                          });
    auto r = co_await c.server_status(0xCAFEBABEu, 2s);
    EXPECT_TRUE(r.has_value());
    if(!r) co_return;
    EXPECT_EQ(r->users, 100u);
    EXPECT_TRUE(saw_encrypted_request);
    EXPECT_TRUE(c.last_response_encrypted());
    c.close(); co_return;
  });
}

TEST(UdpConnection, ServerStatusFallsBackToPlainUdpWhenObfuscatedProbeTimesOut){
  IoRuntime rt;
  udp::socket drop_obfuscated(rt.context(), udp::endpoint(asio::ip::address_v4::loopback(), 0));
  ed2k::test::MockUdpServer plain_server(rt.context());
  plain_server.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter w; w.u32(0xCAFEBABEu); w.u32(42); w.u32(5000);
    co_await ed2k::test::send_packet_to(s, from, udpop::GLOBSERVSTATRES, w.take());
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), plain_server.port(),
                          UdpServerObfuscation{
                              .udp_key = 0x11223344u,
                              .udp_port = drop_obfuscated.local_endpoint().port(),
                              .probe_timeout = 50ms,
                              .fallback_plain = true,
                              .random_key_part = 0xbeef,
                              .marker = 0x42,
                          });
    auto r = co_await c.server_status(0xCAFEBABEu, 2s);
    EXPECT_TRUE(r.has_value());
    if(!r) co_return;
    EXPECT_EQ(r->users, 42u);
    EXPECT_FALSE(c.last_response_encrypted());
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
    codec::ByteWriter w; w.u8(1); w.u32_be(0x01020304u); w.u16(0x1234u);
    co_await ed2k::test::send_packet_to(s, from, udpop::SERVER_LIST_RES, w.take());
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    auto r = co_await c.server_list(IPv4::from_host(0x01020304u), 0x1234u, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->size(), 1u); if(r->size() != 1u) co_return;
    EXPECT_EQ((*r)[0].first.host(), 0x01020304u);
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
TEST(UdpConnection, ServerIdentEventEmitted){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter ident;
    ident.hash16(*MD4Hash::from_hex("00112233445566778899aabbccddeeff"));
    ident.u32_be(0x7F000001u);
    ident.u16(0x1234u);
    ident.u32(2);
    ident.u8(0x82); ident.u8(tag::ST_SERVERNAME); ident.string16("name");
    ident.u8(0x82); ident.u8(tag::ST_DESCRIPTION); ident.string16("desc");
    co_await ed2k::test::send_packet_to(s, from, udpop::SERVER_IDENT, ident.take());
    co_await ed2k::test::send_packet_to(s, from, udpop::GLOBSEARCHRES, search_item("after"));
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    std::string got_name;
    auto sub = c.on_event([&](const UdpEvent& e){
      if(std::holds_alternative<UdpServerIdentEvent>(e)) got_name = std::get<UdpServerIdentEvent>(e).name;
    });
    auto r = co_await c.global_search(Keyword{"foo"}, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(got_name, "name");
    c.close(); co_return;
  });
}
TEST(UdpConnection, DestroyedSubscriptionStopsEvents){
  IoRuntime rt;
  ed2k::test::MockUdpServer srv(rt.context());
  srv.serve([](udp::socket& s, const Packet&, const udp::endpoint& from) -> asio::awaitable<void>{
    codec::ByteWriter ident;
    ident.hash16(*MD4Hash::from_hex("00112233445566778899aabbccddeeff"));
    ident.u32_be(0x7F000001u);
    ident.u16(0x1234u);
    ident.u32(2);
    ident.u8(0x82); ident.u8(tag::ST_SERVERNAME); ident.string16("name");
    ident.u8(0x82); ident.u8(tag::ST_DESCRIPTION); ident.string16("desc");
    co_await ed2k::test::send_packet_to(s, from, udpop::SERVER_IDENT, ident.take());
    co_await ed2k::test::send_packet_to(s, from, udpop::GLOBSEARCHRES, search_item("after"));
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpServerConnection c(rt.executor(), *IPv4::from_dotted("127.0.0.1"), srv.port());
    int calls = 0;
    {
      auto sub = c.on_event([&](const UdpEvent&){ ++calls; });
      (void)sub;
    }
    auto r = co_await c.global_search(Keyword{"foo"}, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(calls, 0);
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
    auto sub = c.on_event([&](const UdpEvent& e){ if(std::holds_alternative<InvalidLowIdEvent>(e)) got_id = std::get<InvalidLowIdEvent>(e).id; });
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
