#include <gtest/gtest.h>
#include <array>
#include <chrono>
#include <exception>
#include <initializer_list>
#include <utility>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"
#include "mock_peer.hpp"   // P2 ed2k::test::MockPeer
using namespace ed2k; using namespace ed2k::peer; using namespace ed2k::net;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

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
static std::vector<std::byte> bytes(std::initializer_list<int> xs){
  std::vector<std::byte> v; for(int x:xs) v.push_back(std::byte(x)); return v;
}
static asio::awaitable<void> send_pkt(tcp::socket& s, std::uint8_t opcode, std::span<const std::byte> payload, std::uint8_t proto_val = proto::eDonkey){
  Packet p; p.protocol=proto_val; p.opcode=opcode; p.payload.assign(payload.begin(), payload.end());
  auto frame = encode_frame(p);
  auto [e,n] = co_await asio::async_write(s, asio::buffer(frame), asio::as_tuple(asio::use_awaitable));
  (void)e;(void)n; co_return;
}
static asio::awaitable<std::vector<std::byte>> read_frame(tcp::socket& s){
  std::array<std::byte,5> hdr;
  auto [e1,n1] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
  (void)n1; if(e1) co_return std::vector<std::byte>{};
  auto h = parse_header(hdr); if(!h) co_return std::vector<std::byte>{};
  std::vector<std::byte> body(h->size);
  auto [e2,n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
  (void)n2; if(e2) co_return std::vector<std::byte>{};
  co_return body;
}
static asio::awaitable<void> keep_alive(tcp::socket& s){
  std::array<std::byte,1> t; auto [e,n]=co_await asio::async_read(s,asio::buffer(t),asio::as_tuple(asio::use_awaitable)); (void)e;(void)n; co_return;
}
static HelloInfo peer_hello(){ HelloInfo h; h.nickname="peer"; h.version=0x3C; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff"); return h; }
static int hexval(char c){ return c<='9'? c-'0' : (c|0x20)-'a'+10; }
static std::array<std::byte,20> sha1_from_hex(std::string_view h){
  std::array<std::byte,20> out{};
  for(std::size_t b=0;b<20 && 2*b+1<h.size();++b) out[b]=std::byte(hexval(h[2*b])*16+hexval(h[2*b+1]));
  return out;
}
static AICHHash aich_from_hex(std::string_view h){ return AICHHash::from_bytes(sha1_from_hex(h)); }
// 读一帧并返回 [proto(1)][body=opcode+payload]; 供 AICH 测试断言协议层字节(OP_EMULEPROT 0xC5)。
static asio::awaitable<std::pair<std::uint8_t,std::vector<std::byte>>> read_frame_proto(tcp::socket& s){
  using R = std::pair<std::uint8_t,std::vector<std::byte>>;
  std::array<std::byte,5> hdr;
  auto [e1,n1] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
  (void)n1; if(e1) co_return R{0, {}};
  std::uint8_t proto_byte = std::to_integer<std::uint8_t>(hdr[0]);
  auto h = parse_header(hdr); if(!h) co_return R{0, {}};
  std::vector<std::byte> body(h->size);
  auto [e2,n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
  (void)n2; if(e2) co_return R{0, {}};
  co_return R{proto_byte, std::move(body)};
}

TEST(C2CConnection, HandshakeRoundTrip){
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);                       // 收 HELLO
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(peer_hello()));
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto r = co_await c.handshake(peer_hello(), 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->nickname, "peer");
    c.close(); co_return;
  });
}
TEST(C2CConnection, RequestFileStatus){
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);                       // 收 HELLO
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(peer_hello()));
    (void)co_await read_frame(s);                       // 收 SETREQFILEID
    codec::ByteWriter w; w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff")); w.u16(2); w.u8(0x01); w.u8(0x00);
    co_await send_pkt(s, op::FILESTATUS, w.take());
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    (void)co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    (void)co_await c.handshake(peer_hello(), 2s);
    auto r = co_await c.request_file(*FileHash::from_hex("00112233445566778899aabbccddeeff"), 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->parts.size(), 2u); if(r->parts.size()!=2u) co_return;
    EXPECT_TRUE(r->parts[0]); EXPECT_FALSE(r->parts[1]);
    c.close(); co_return;
  });
}
TEST(C2CConnection, RequestHashset){
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s); co_await send_pkt(s, op::HELLOANSWER, encode_hello(peer_hello()));
    (void)co_await read_frame(s);
    codec::ByteWriter w; w.u16(1); w.hash16(*PartHash::from_hex("11111111111111111111111111111111"));
    co_await send_pkt(s, op::HASHSETANSWER, w.take());
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    (void)co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    (void)co_await c.handshake(peer_hello(), 2s);
    auto r = co_await c.request_hashset(*FileHash::from_hex("00112233445566778899aabbccddeeff"), 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->size(), 1u); if(r->size()!=1u) co_return;
    c.close(); co_return;
  });
}
TEST(C2CConnection, StartUploadAccepted){
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s); co_await send_pkt(s, op::HELLOANSWER, encode_hello(peer_hello()));
    (void)co_await read_frame(s);                       // SETREQFILEID
    { codec::ByteWriter w; w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff")); w.u16(1); w.u8(0x01);
      co_await send_pkt(s, op::FILESTATUS, w.take()); }
    (void)co_await read_frame(s);                       // HASHSETREQUEST
    { codec::ByteWriter w; w.u16(1); w.hash16(*PartHash::from_hex("11111111111111111111111111111111"));
      co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
    (void)co_await read_frame(s);                       // STARTUPLOADREQ
    co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    (void)co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    (void)co_await c.handshake(peer_hello(), 2s);
    auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
    (void)co_await c.request_file(h, 2s);
    (void)co_await c.request_hashset(h, 2s);
    auto r = co_await c.start_upload(h, 2s);
    EXPECT_TRUE(r.has_value());
    c.close(); co_return;
  });
}
TEST(C2CConnection, StartUploadQueued){
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s); co_await send_pkt(s, op::HELLOANSWER, encode_hello(peer_hello()));
    (void)co_await read_frame(s);                       // SETREQFILEID
    { codec::ByteWriter w; w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff")); w.u16(1); w.u8(0x01);
      co_await send_pkt(s, op::FILESTATUS, w.take()); }
    (void)co_await read_frame(s);                       // HASHSETREQUEST
    { codec::ByteWriter w; w.u16(1); w.hash16(*PartHash::from_hex("11111111111111111111111111111111"));
      co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
    (void)co_await read_frame(s);                       // STARTUPLOADREQ
    { codec::ByteWriter w; w.u16(5);
      co_await send_pkt(s, op::QUEUERANKING, w.take()); }
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    (void)co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    (void)co_await c.handshake(peer_hello(), 2s);
    auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
    (void)co_await c.request_file(h, 2s); (void)co_await c.request_hashset(h, 2s);
    auto r = co_await c.start_upload(h, 2s);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::upload_queued));
    c.close(); co_return;
  });
}
TEST(C2CConnection, RequestBlocksRoundTrip){
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s); co_await send_pkt(s, op::HELLOANSWER, encode_hello(peer_hello()));
    (void)co_await read_frame(s);                       // SETREQFILEID
    { codec::ByteWriter w; w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff")); w.u16(1); w.u8(0x01);
      co_await send_pkt(s, op::FILESTATUS, w.take()); }
    (void)co_await read_frame(s);                       // HASHSETREQUEST
    { codec::ByteWriter w; w.u16(1); w.hash16(*PartHash::from_hex("11111111111111111111111111111111"));
      co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
    (void)co_await read_frame(s); co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});   // STARTUPLOADREQ + ACCEPT
    (void)co_await read_frame(s);                       // REQUESTPARTS
    { codec::ByteWriter w; w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff")); w.u32(0); w.u32(10); w.blob(bytes({1,2,3,4,5,6,7,8,9,10}));
      co_await send_pkt(s, op::SENDINGPART, w.take()); }
    co_await send_pkt(s, op::OUTOFPARTREQS, {});        // 告知无更多块 → 终止多响应循环
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    (void)co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    (void)co_await c.handshake(peer_hello(), 2s);
    auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
    (void)co_await c.request_file(h, 2s); (void)co_await c.request_hashset(h, 2s); (void)co_await c.start_upload(h, 2s);
    auto r = co_await c.request_blocks(h, {0,0,0}, {10,0,0}, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->size(), 1u); if(r->size()!=1u) co_return;
    EXPECT_EQ((*r)[0].data.size(), 10u);
    c.close(); co_return;
  });
}
TEST(C2CConnection, FileNotFound){
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s); co_await send_pkt(s, op::HELLOANSWER, encode_hello(peer_hello()));
    (void)co_await read_frame(s);                       // SETREQFILEID
    co_await send_pkt(s, op::FILEREQANSNOFIL, encode_set_req_file(*FileHash::from_hex("00112233445566778899aabbccddeeff")));
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    (void)co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    (void)co_await c.handshake(peer_hello(), 2s);
    auto r = co_await c.request_file(*FileHash::from_hex("00112233445566778899aabbccddeeff"), 2s);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::file_not_found));
    c.close(); co_return;
  });
}
TEST(C2CConnection, RequestAichProofRoundTrip){
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  FileHash fh = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  AICHHash master = aich_from_hex("00112233445566778899aabbccddeeff00112233");
  std::array<std::byte,20> proof_hash = sha1_from_hex("aabbccddeeff00112233445566778899aabbccdd");
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    // request_aich_proof 只发 AICHREQUEST 收 AICHANSWER, 不需握手;协议层必须 OP_EMULEPROT(0xC5)。
    auto [proto_byte, body] = co_await read_frame_proto(s);
    EXPECT_EQ(proto_byte, proto::eMule);                  // interop-critical: AICH under OP_EMULEPROT
    EXPECT_FALSE(body.empty()); if(body.empty()) co_return;
    // body = [opcode(1)][file_hash(16)][part_index(2)][master_hash(20)] = 39B
    EXPECT_EQ(body.size(), 1u + 38u); if(body.size() != 39u) co_return;
    EXPECT_EQ(body[0], std::byte(op::AICHREQUEST));
    EXPECT_EQ(std::to_integer<std::uint8_t>(body[17]), 7u);   // part_index LE low (偏移 1+16)
    EXPECT_EQ(std::to_integer<std::uint8_t>(body[18]), 0u);
    std::array<std::byte,20> got_master{}; for(int i=0;i<20;++i) got_master[i]=body[19+i];
    EXPECT_EQ(got_master, master.bytes());                    // master_hash 偏移 19..39
    // answer: file_hash(16)+part_index(2)+master_hash(20)+V2(count16=1,ident=0,hash; count32=0)
    codec::ByteWriter w; w.hash16(fh); w.u16(7); w.hash20(master.bytes());
    w.u16(1); w.u16(0); w.hash20(proof_hash); w.u16(0);
    co_await send_pkt(s, op::AICHANSWER, w.take(), proto::eMule);
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto r = co_await c.request_aich_proof(fh, master, 7, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->hashes.size(), 1u); if(r->hashes.size()!=1u) co_return;
    EXPECT_EQ(r->hashes[0].identifier, 0u);
    EXPECT_EQ(r->hashes[0].hash, proof_hash);
    c.close(); co_return;
  });
}
TEST(C2CConnection, RequestAichMasterHashRoundTrip){
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  FileHash fh = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  AICHHash master = aich_from_hex("00112233445566778899aabbccddeeff00112233");
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    auto [proto_byte, body] = co_await read_frame_proto(s);
    EXPECT_EQ(proto_byte, proto::eMule);
    EXPECT_FALSE(body.empty()); if(body.empty()) co_return;
    EXPECT_EQ(body.size(), 1u + 16u); if(body.size() != 17u) co_return;   // opcode+file_hash
    EXPECT_EQ(body[0], std::byte(op::AICHFILEHASHREQ));
    // answer: file_hash(16) + aich_master_hash(20)
    codec::ByteWriter w; w.hash16(fh); w.hash20(master.bytes());
    co_await send_pkt(s, op::AICHFILEHASHANS, w.take(), proto::eMule);
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto r = co_await c.request_aich_master_hash(fh, 2s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(r->bytes(), master.bytes());
    c.close(); co_return;
  });
}
TEST(C2CConnection, RequestAichProofMasterMismatch){
  // 回显的 master_hash 与请求不一致 → hash_mismatch (aMule DownloadClient.cpp:1634 守卫)
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  FileHash fh = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  AICHHash master = aich_from_hex("00112233445566778899aabbccddeeff00112233");
  AICHHash wrong = aich_from_hex("ff112233445566778899aabbccddeeff00112233");
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);                          // 丢弃 AICHREQUEST
    codec::ByteWriter w; w.hash16(fh); w.u16(7); w.hash20(wrong.bytes());   // 回显错误 master
    w.u16(0); w.u16(0);                                    // V2: count16=0, count32=0
    co_await send_pkt(s, op::AICHANSWER, w.take(), proto::eMule);
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto r = co_await c.request_aich_proof(fh, master, 7, 2s);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::hash_mismatch));
    c.close(); co_return;
  });
}
TEST(C2CConnection, RequestFileTimesOut){
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s); co_await send_pkt(s, op::HELLOANSWER, encode_hello(peer_hello()));
    (void)co_await read_frame(s);                       // SETREQFILEID — 不回
    co_await keep_alive(s); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    (void)co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    (void)co_await c.handshake(peer_hello(), 2s);
    auto r = co_await c.request_file(*FileHash::from_hex("00112233445566778899aabbccddeeff"), 200ms);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::timed_out));
    c.close(); co_return;
  });
}
