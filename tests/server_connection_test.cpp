#include <gtest/gtest.h>
#include <array>
#include <chrono>
#include <exception>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/server/connection.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/server/search_query.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"
#include "mock_server.hpp"
using namespace ed2k; using namespace ed2k::server; using namespace ed2k::net;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(),
    [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart();
  EXPECT_TRUE(done);
}
static asio::awaitable<std::vector<std::byte>> read_frame(tcp::socket& s){
  std::array<std::byte,5> hdr;
  auto [e1,n1] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
  (void)n1; if(e1) co_return std::vector<std::byte>{};
  auto h = parse_header(hdr);
  if(!h) co_return std::vector<std::byte>{};
  std::vector<std::byte> body(h->size);
  auto [e2,n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
  (void)n2; if(e2) co_return std::vector<std::byte>{};
  co_return body;
}
static asio::awaitable<void> keep_alive(tcp::socket& s){
  std::array<std::byte,1> t;
  auto [e,n] = co_await asio::async_read(s, asio::buffer(t), asio::as_tuple(asio::use_awaitable));
  (void)e;(void)n; co_return;
}
static std::vector<std::byte> msg_payload(std::string_view s){ codec::ByteWriter w; w.string16(s); return w.take(); }
static std::vector<std::byte> status_payload(std::uint32_t u, std::uint32_t f){ codec::ByteWriter w; w.u32(u); w.u32(f); return w.take(); }
static std::vector<std::byte> idchange_payload(std::uint32_t id, std::uint32_t flags){ codec::ByteWriter w; w.u32(id); w.u32(flags); return w.take(); }
static std::vector<std::byte> cb_payload(std::uint32_t ip, std::uint16_t port){ codec::ByteWriter w; w.u32_be(ip); w.u16(port); return w.take(); }

TEST(ServerConnection, LoginHighId){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::SERVERMESSAGE, msg_payload("Welcome"));
    co_await ed2k::test::send_packet(s, op::SERVERSTATUS, status_payload(100, 5000));
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    std::vector<ServerEvent> evs;
    c.on_event([&](const ServerEvent& e){ evs.push_back(e); });
    LoginParams p; p.nickname="u"; p.client_port=4662;
    p.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
    auto r = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_TRUE(r->high_id);
    EXPECT_EQ(r->client_id, 0x01000000u);
    EXPECT_GE(evs.size(), 2u);
    c.close(); co_return;
  });
}
TEST(ServerConnection, LoginLowId){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(5u, 0u));
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    LoginParams p; p.nickname="u";
    auto r = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_FALSE(r->high_id);
    c.close(); co_return;
  });
}
TEST(ServerConnection, LoginEmitsMessageAndStatus){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::SERVERMESSAGE, msg_payload("Hi"));
    co_await ed2k::test::send_packet(s, op::SERVERSTATUS, status_payload(7, 8));
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0u));
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    std::vector<ServerEvent> evs;
    c.on_event([&](const ServerEvent& e){ evs.push_back(e); });
    LoginParams p; p.nickname="u";
    auto r = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    bool got_msg=false, got_status=false;
    for(auto& e:evs){
      if(std::holds_alternative<ServerMessageEvent>(e)) got_msg = (std::get<ServerMessageEvent>(e).text=="Hi");
      if(std::holds_alternative<ServerStatusEvent>(e)){ auto& st=std::get<ServerStatusEvent>(e); got_status = (st.users==7 && st.files==8); }
    }
    EXPECT_TRUE(got_msg);
    EXPECT_TRUE(got_status);
    c.close(); co_return;
  });
}
TEST(ServerConnection, LoginRejected){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::REJECT);
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    LoginParams p; p.nickname="u";
    auto r = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::login_rejected));
    c.close(); co_return;
  });
}
TEST(ServerConnection, SearchRoundTrip){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0u));
    (void)co_await read_frame(s);                                       // SEARCHREQUEST
    codec::ByteWriter w; w.u32(1);
    auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
    w.hash16(h); w.u32(0xDDCCBBAAu); w.u16(0x1234u); w.u32(1);
    w.u8(0x82); w.u8(tag::FT_FILENAME); w.string16("plain");
    co_await ed2k::test::send_packet(s, op::SEARCHRESULT, w.take());
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    LoginParams p; p.nickname="u";
    auto lr = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;
    auto r = co_await c.search(Keyword{"foo"}, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->size(), 1u);
    if(r->size()!=1u) co_return;
    EXPECT_EQ((*r)[0].name, "plain");
    c.close(); co_return;
  });
}
TEST(ServerConnection, SearchZlibResultInflated){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0u));
    (void)co_await read_frame(s);
    codec::ByteWriter w; w.u32(1);
    auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
    w.hash16(h); w.u32(0xDDCCBBAAu); w.u16(0x1234u); w.u32(1);
    w.u8(0x82); w.u8(tag::FT_FILENAME); w.string16("zlib");
    co_await ed2k::test::send_zlib_packet(s, op::SEARCHRESULT, w.take());  // 0xD4 压缩
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    LoginParams p; p.nickname="u";
    auto lr = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;
    auto r = co_await c.search(Keyword{"foo"}, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;        // P2 recv 已透明解压 0xD4
    EXPECT_EQ(r->size(), 1u);
    if(r->size()!=1u) co_return;
    EXPECT_EQ((*r)[0].name, "zlib");
    c.close(); co_return;
  });
}
TEST(ServerConnection, GetSourcesRoundTrip){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0u));
    (void)co_await read_frame(s);                                       // GETSOURCES
    codec::ByteWriter w;
    auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
    w.hash16(h); w.u8(2);
    w.u32(0x01000000u); w.u16(0x1234u);                                  // HighID 源
    w.u32(5u); w.u16(0x5678u);                                           // LowID 源
    co_await ed2k::test::send_packet(s, op::FOUNDSOURCES, w.take());
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    LoginParams p; p.nickname="u";
    auto lr = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;
    auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
    auto r = co_await c.get_sources(h, 100, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->sources.size(), 2u);
    if(r->sources.size()!=2u) co_return;
    EXPECT_FALSE(r->sources[0].low_id());
    EXPECT_TRUE(r->sources[1].low_id());
    c.close(); co_return;
  });
}
TEST(ServerConnection, CallbackRequestedEmitted){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0u));
    co_await ed2k::test::send_packet(s, op::CALLBACKREQUESTED, cb_payload(0x0D0C0B0Au, 0x1234u));
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    std::vector<ServerEvent> evs;
    c.on_event([&](const ServerEvent& e){ evs.push_back(e); });
    LoginParams p; p.nickname="u";
    auto lr = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;
    auto er = co_await c.receive_events(2s);
    EXPECT_TRUE(er.has_value());
    bool got_cb=false;
    for(auto& e:evs){
      if(std::holds_alternative<CallbackRequestedEvent>(e)){
        auto& cb=std::get<CallbackRequestedEvent>(e);
        got_cb = (cb.ip.value==0x0D0C0B0Au && cb.port==0x1234u);
      }
    }
    EXPECT_TRUE(got_cb);
    c.close(); co_return;
  });
}
TEST(ServerConnection, SearchTimesOut){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  srv.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0u));
    (void)co_await read_frame(s);                                       // SEARCH — 不回
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    LoginParams p; p.nickname="u";
    auto lr = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;
    auto r = co_await c.search(Keyword{"foo"}, 200ms);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::timed_out));
    c.close(); co_return;
  });
}
TEST(ServerConnection, CallbackRequestSendsEncodedFrame){
  IoRuntime rt;
  ed2k::test::MockServer srv(rt.context());
  std::uint32_t captured = 0;
  std::uint8_t captured_opcode = 0;
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    auto f = co_await read_frame(s);   // 第一帧 LOGINREQUEST
    (void)f;
    co_await ed2k::test::send_packet(s, op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    auto f2 = co_await read_frame(s);   // 第二帧 CALLBACKREQUEST
    // read_frame 返回的 body 含 opcode 首字节（parse_header.size = opcode+payload），先 u8 跳过再读 u32
    if(f2.size() >= 5){
      codec::ByteReader r(f2);
      captured_opcode = r.u8();
      captured = r.u32();
    }
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    ServerConnection c(rt.executor());
    LoginParams p; p.nickname="u"; p.client_port=4662;
    p.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
    auto lr = co_await c.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 2s);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;
    auto cr = co_await c.callback_request(0x00001234u, 2s);
    EXPECT_TRUE(cr.has_value());
    c.close(); co_return;
  });
  EXPECT_EQ(captured_opcode, op::CALLBACKREQUEST);
  EXPECT_EQ(captured, 0x00001234u);
}
