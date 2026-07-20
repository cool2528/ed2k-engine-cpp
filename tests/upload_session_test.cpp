#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/experimental/channel.hpp>
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/net/encrypted_stream_socket.hpp"
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/download/aich_checker.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include "ed2k/share/client_credits.hpp"
#include "ed2k/share/known_file.hpp"
#include "ed2k/share/upload_queue.hpp"
#include "ed2k/share/upload_session.hpp"
#include "ed2k/share/upload_throttler.hpp"
#include "mock_peer.hpp"

using namespace ed2k;
using namespace ed2k::peer;
using namespace ed2k::share;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

template <class F> static void run_coro(ed2k::net::IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(),
    [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart();
  EXPECT_TRUE(done);
}

static HelloInfo hello(std::string name){
  HelloInfo h;
  h.nickname = std::move(name);
  h.version = 0x3C;
  h.port = 4662;
  h.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
  return h;
}

static HelloInfo hello_without_compression(std::string name){
  auto h = hello(std::move(name));
  h.supports_compression = false;
  return h;
}

static HelloInfo hello_with_hash(std::string name, std::string_view hash){
  auto h = hello(std::move(name));
  h.user_hash = *UserHash::from_hex(hash);
  return h;
}

static std::filesystem::path temp_file(std::string name){
  return std::filesystem::temp_directory_path() / std::move(name);
}

static std::vector<std::byte> sample_data(std::size_t n){
  std::vector<std::byte> data(n);
  for(std::size_t i=0;i<n;++i) data[i]=std::byte((i*37u + 11u) & 0xFFu);
  return data;
}

static std::vector<std::byte> incompressible_data(std::size_t n){
  std::vector<std::byte> data(n);
  std::uint32_t x = 0x12345678u;
  for(std::size_t i = 0; i < n; ++i) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    data[i] = std::byte(x & 0xFFu);
  }
  return data;
}

static std::vector<std::byte> partially_compressible_data(std::size_t n){
  std::vector<std::byte> data(n, std::byte{0});
  auto noise = incompressible_data(n / 2);
  std::copy(noise.begin(), noise.end(), data.begin());
  return data;
}

static void write_file(const std::filesystem::path& path, std::span<const std::byte> data){
  std::ofstream f(path, std::ios::binary|std::ios::trunc);
  f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

static KnownFile known_file_for(const std::filesystem::path& path, std::span<const std::byte> data){
  KnownFile f;
  auto h = hash_bytes(data);
  f.hash = h.file_hash;
  f.part_hashes = std::move(h.part_hashes);
  f.aich_root = aich_hash_bytes(data);
  f.name = path.filename().string();
  f.path = path;
  f.size = data.size();
  return f;
}

TEST(UploadSession, IpFilterRejectsRemoteBeforeHandshake) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    tcp::acceptor acceptor(rt.context(), tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
    KnownFileDB db;
    auto filter = std::make_shared<ed2k::infra::IPFilter>();
    filter->add(ed2k::infra::IPRange{
        .start = *IPv4::from_dotted("127.0.0.1"),
        .end = *IPv4::from_dotted("127.0.0.1"),
        .level = 200,
        .name = "loopback",
    });

    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void> {
      auto [accept_ec, socket] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
      EXPECT_FALSE(accept_ec);
      if (accept_ec) {
        co_return;
      }
      UploadSession session(std::move(socket), db, hello("server"));
      session.set_ip_filter(filter, 127);
      auto r = co_await session.run(200ms);
      EXPECT_FALSE(r.has_value());
      if (!r) {
        EXPECT_EQ(r.error(), make_error_code(errc::ip_filtered));
      }
      co_return;
    }, asio::detached);

    tcp::socket client(rt.context());
    auto [connect_ec] = co_await client.async_connect(
        tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), acceptor.local_endpoint().port()),
        asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(connect_ec);
    co_return;
  });
}

TEST(UploadSession, EncryptedNegotiatedInboundStreamReadsAndWritesPackets) {
  net::IoRuntime rt;
  InboundListener listener(rt.executor(), 0);
  KnownFileDB db;
  boost::asio::experimental::channel<void(boost::system::error_code, bool)> server_ready(rt.executor(), 1);
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void> {
    auto accepted = co_await listener.accept_peer(
        hello("server").user_hash, ObfuscationPolicy::preferred, 1s);
    if (!accepted) {
      server_ready.try_send(boost::system::error_code{}, false);
      co_return;
    }
    UploadSession session(std::move(*accepted), db, hello("server"));
    server_ready.try_send(boost::system::error_code{}, true);
    (void)co_await session.run(1s);
    co_return;
  }, asio::detached);

  run_coro(rt, [&]() -> asio::awaitable<void> {
    net::EncryptedStreamSocket client(rt.executor());
    auto connected = co_await client.connect(*IPv4::from_dotted("127.0.0.1"),
                                             listener.local_port(), 1s);
    EXPECT_TRUE(connected.has_value());
    if (!connected) co_return;
    auto negotiated = co_await client.handshake_initiator(hello("server").user_hash, 1s);
    EXPECT_TRUE(negotiated.has_value());
    if (!negotiated) co_return;
    EXPECT_TRUE(co_await server_ready.async_receive(asio::use_awaitable));

    net::Packet hello_packet;
    hello_packet.protocol = net::proto::eDonkey;
    hello_packet.opcode = op::HELLO;
    hello_packet.payload = encode_hello_packet(hello("encrypted-client"));
    EXPECT_TRUE((co_await client.send(hello_packet)).has_value());
    auto answer = co_await client.recv(1s);
    EXPECT_TRUE(answer.has_value());
    if (!answer) co_return;
    EXPECT_EQ(answer->opcode, op::HELLOANSWER);

    net::Packet request;
    request.protocol = net::proto::eDonkey;
    request.opcode = op::SETREQFILEID;
    request.payload = encode_set_req_file(FileHash{});
    EXPECT_TRUE((co_await client.send(request)).has_value());
    auto not_found = co_await client.recv(1s);
    EXPECT_TRUE(not_found.has_value());
    if (not_found) EXPECT_EQ(not_found->opcode, op::FILEREQANSNOFIL);
    client.close();
    co_return;
  });
}

static asio::awaitable<void> send_pkt(tcp::socket& s, std::uint8_t opcode, std::span<const std::byte> payload, std::uint8_t proto_val = ed2k::net::proto::eDonkey){
  ed2k::net::Packet p;
  p.protocol=proto_val;
  p.opcode=opcode;
  p.payload.assign(payload.begin(), payload.end());
  auto frame = ed2k::net::encode_frame(p);
  auto [e,n] = co_await asio::async_write(s, asio::buffer(frame), asio::as_tuple(asio::use_awaitable));
  (void)e; (void)n; co_return;
}

static asio::awaitable<ed2k::net::Packet> read_packet(tcp::socket& s){
  std::array<std::byte,5> hdr;
  auto [e1,n1] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
  (void)n1; if(e1) co_return ed2k::net::Packet{};
  auto h = ed2k::net::parse_header(hdr);
  if(!h) co_return ed2k::net::Packet{};
  std::vector<std::byte> body(h->size);
  auto [e2,n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
  (void)n2; if(e2) co_return ed2k::net::Packet{};
  auto pkt = ed2k::net::assemble(h->protocol, body);
  if(!pkt) co_return ed2k::net::Packet{};
  co_return std::move(*pkt);
}

TEST(UploadSession, AnswersFilenameStatusAndHashset){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "shared.bin";
  f.size = 20000000;
  f.part_hashes = {
    *PartHash::from_hex("11111111111111111111111111111111"),
    *PartHash::from_hex("22222222222222222222222222222222")
  };
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"));
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto hs = co_await c.handshake(hello("client"), 2s);
    EXPECT_TRUE(hs.has_value()); if(!hs) co_return;

    auto name = co_await c.request_filename(f.hash, 2s);
    EXPECT_TRUE(name.has_value()); if(!name) co_return;
    EXPECT_EQ(*name, "shared.bin");

    auto status = co_await c.request_file(f.hash, 2s);
    EXPECT_TRUE(status.has_value()); if(!status) co_return;
    EXPECT_TRUE(status->parts.empty());

    auto hashes = co_await c.request_hashset(f.hash, 2s);
    EXPECT_TRUE(hashes.has_value()); if(!hashes) co_return;
    EXPECT_EQ(*hashes, f.part_hashes);
    c.close();
    co_return;
  });
}

TEST(UploadSession, SendsRequestedBlockData){
  ed2k::net::IoRuntime rt;
  auto data = sample_data(15000);
  auto path = temp_file("ed2k-upload-session-block.bin");
  write_file(path, data);
  KnownFileDB db;
  auto f = known_file_for(path, data);
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto hs = co_await c.handshake(hello("client"), 2s);
    EXPECT_TRUE(hs.has_value()); if(!hs) co_return;

    auto blocks = co_await c.request_blocks(f.hash, {1000,0,0}, {14000,0,0}, 2s);
    EXPECT_TRUE(blocks.has_value()); if(!blocks) co_return;
    EXPECT_EQ(blocks->size(), 1u); if(blocks->size() != 1u) co_return;
    EXPECT_EQ((*blocks)[0].start, 1000u);
    EXPECT_EQ((*blocks)[0].end, 14000u);
    std::vector<std::byte> expected(data.begin()+1000, data.begin()+14000);
    EXPECT_EQ((*blocks)[0].data, expected);
    c.close();
    co_return;
  });
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(UploadSession, SplitsSendingPartFramesAtAMuleChunkSize){
  ed2k::net::IoRuntime rt;
  auto data = sample_data(25000);
  auto path = temp_file("ed2k-upload-session-split.bin");
  write_file(path, data);
  KnownFileDB db;
  auto f = known_file_for(path, data);
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello_without_compression("client")));
    auto hello_ans = co_await read_packet(s);
    EXPECT_EQ(hello_ans.opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::REQUESTPARTS, encode_request_parts(f.hash, {0,0,0}, {25000,0,0}));

    auto p1 = co_await read_packet(s);
    auto p2 = co_await read_packet(s);
    auto p3 = co_await read_packet(s);
    EXPECT_EQ(p1.opcode, op::SENDINGPART);
    EXPECT_EQ(p2.opcode, op::SENDINGPART);
    EXPECT_EQ(p3.opcode, op::SENDINGPART);
    auto b1 = decode_sending_part(p1.payload);
    auto b2 = decode_sending_part(p2.payload);
    auto b3 = decode_sending_part(p3.payload);
    EXPECT_TRUE(b1.has_value()); if(!b1) co_return;
    EXPECT_TRUE(b2.has_value()); if(!b2) co_return;
    EXPECT_TRUE(b3.has_value()); if(!b3) co_return;
    EXPECT_EQ(b1->start, 0u);
    EXPECT_EQ(b1->end, 10240u);
    EXPECT_EQ(b2->start, 10240u);
    EXPECT_EQ(b2->end, 20480u);
    EXPECT_EQ(b3->start, 20480u);
    EXPECT_EQ(b3->end, 25000u);
    s.close();
    co_return;
  });
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(UploadSession, SendsCompressedPartWhenCompressionSavesBytes){
  ed2k::net::IoRuntime rt;
  std::vector<std::byte> data(25000, std::byte{0});
  auto path = temp_file("ed2k-upload-session-compressed.bin");
  write_file(path, data);
  KnownFileDB db;
  auto f = known_file_for(path, data);
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    auto hello_ans = co_await read_packet(s);
    EXPECT_EQ(hello_ans.opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::REQUESTPARTS, encode_request_parts(f.hash, {0,0,0}, {25000,0,0}));

    auto p = co_await read_packet(s);
    EXPECT_EQ(p.protocol, ed2k::net::proto::eMule);
    EXPECT_EQ(p.opcode, op::COMPRESSEDPART);
    auto block = decode_compressed_part(p.payload);
    EXPECT_TRUE(block.has_value()); if(!block) co_return;
    EXPECT_EQ(block->hash, f.hash);
    EXPECT_EQ(block->start, 0u);
    EXPECT_EQ(block->end, data.size());
    EXPECT_EQ(block->data, data);
    s.close();
    co_return;
  });
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(UploadSession, SplitsCompressedPartFramesAtAMuleChunkSize){
  ed2k::net::IoRuntime rt;
  auto data = partially_compressible_data(50000);
  auto path = temp_file("ed2k-upload-session-compressed-split.bin");
  write_file(path, data);
  KnownFileDB db;
  auto f = known_file_for(path, data);
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    auto hello_ans = co_await read_packet(s);
    EXPECT_EQ(hello_ans.opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::REQUESTPARTS, encode_request_parts(f.hash, {0,0,0}, {static_cast<std::uint32_t>(data.size()),0,0}));

    std::vector<std::byte> compressed;
    std::optional<std::uint32_t> compressed_size;
    std::size_t frame_count = 0;
    while(true) {
      auto p = co_await read_packet(s);
      EXPECT_EQ(p.protocol, ed2k::net::proto::eMule);
      EXPECT_EQ(p.opcode, op::COMPRESSEDPART);
      auto seg = decode_compressed_part_segment(p.payload);
      EXPECT_TRUE(seg.has_value()); if(!seg) co_return;
      EXPECT_EQ(seg->hash, f.hash);
      EXPECT_EQ(seg->start, 0u);
      if(!compressed_size) compressed_size = seg->compressed_size;
      EXPECT_EQ(seg->compressed_size, *compressed_size);
      compressed.insert(compressed.end(), seg->data.begin(), seg->data.end());
      ++frame_count;
      if(compressed.size() >= *compressed_size) break;
    }

    EXPECT_GT(frame_count, 1u);
    EXPECT_TRUE(compressed_size.has_value()); if(!compressed_size) co_return;
    EXPECT_EQ(compressed.size(), *compressed_size);
    ed2k::codec::ByteWriter w;
    w.hash16(f.hash);
    w.u32(0);
    w.u32(*compressed_size);
    w.blob(compressed);
    auto block = decode_compressed_part(w.take());
    EXPECT_TRUE(block.has_value()); if(!block) co_return;
    EXPECT_EQ(block->data, data);
    s.close();
    co_return;
  });
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(UploadSession, SendsUncompressedPartWhenCompressionDoesNotShrink){
  ed2k::net::IoRuntime rt;
  auto data = incompressible_data(4096);
  auto path = temp_file("ed2k-upload-session-no-compression-benefit.bin");
  write_file(path, data);
  KnownFileDB db;
  auto f = known_file_for(path, data);
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    auto hello_ans = co_await read_packet(s);
    EXPECT_EQ(hello_ans.opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::REQUESTPARTS, encode_request_parts(f.hash, {0,0,0}, {4096,0,0}));

    auto p = co_await read_packet(s);
    EXPECT_EQ(p.protocol, ed2k::net::proto::eDonkey);
    EXPECT_EQ(p.opcode, op::SENDINGPART);
    auto block = decode_sending_part(p.payload);
    EXPECT_TRUE(block.has_value()); if(!block) co_return;
    EXPECT_EQ(block->data, data);
    s.close();
    co_return;
  });
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(UploadSession, AnswersAichMasterHashRequest){
  ed2k::net::IoRuntime rt;
  auto data = sample_data(4096);
  auto path = temp_file("ed2k-upload-session-aich.bin");
  write_file(path, data);
  KnownFileDB db;
  auto f = known_file_for(path, data);
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto hs = co_await c.handshake(hello("client"), 2s);
    EXPECT_TRUE(hs.has_value()); if(!hs) co_return;

    auto master = co_await c.request_aich_master_hash(f.hash, 2s);
    EXPECT_TRUE(master.has_value()); if(!master) co_return;
    EXPECT_EQ(*master, f.aich_root);
    c.close();
    co_return;
  });
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(UploadSession, AnswersAichRecoveryRequest){
  ed2k::net::IoRuntime rt;
  auto data = sample_data(AICH_BLOCK_SIZE * 3);
  auto path = temp_file("ed2k-upload-session-aich-recovery.bin");
  write_file(path, data);
  KnownFileDB db;
  auto f = known_file_for(path, data);
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto hs = co_await c.handshake(hello("client"), 2s);
    EXPECT_TRUE(hs.has_value()); if(!hs) co_return;

    auto proof = co_await c.request_aich_proof(f.hash, f.aich_root, 0, 2s);
    EXPECT_TRUE(proof.has_value()); if(!proof) co_return;
    ed2k::download::AICHChecker checker{f.aich_root, f.size};
    std::span<const std::byte> block0(data.data(), AICH_BLOCK_SIZE);
    std::span<const std::byte> block2(data.data() + AICH_BLOCK_SIZE * 2, AICH_BLOCK_SIZE);
    EXPECT_TRUE(checker.verify_block(0, 0, block0, proof->hashes));
    EXPECT_TRUE(checker.verify_block(0, 2, block2, proof->hashes));
    c.close();
    co_return;
  });
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(UploadSession, AcceptsStartUploadWhenQueueSlotAvailable){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "queued.bin";
  f.size = 1;
  db.add(f);
  UploadQueue queue(1);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor(), &queue);
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    auto hello_ans = co_await read_packet(s);
    EXPECT_EQ(hello_ans.opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::STARTUPLOADREQ, encode_start_upload(f.hash));
    auto ans = co_await read_packet(s);
    EXPECT_EQ(ans.opcode, op::ACCEPTUPLOADREQ);
    EXPECT_TRUE(ans.payload.empty());
    s.close();
    co_return;
  });
}

// STARTUPLOADREQ 命中已知文件时应累加该文件的请求计数
TEST(UploadSession, StartUploadReqIncrementsRequestCount){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "queued.bin";
  f.size = 1;
  db.add(f);
  UploadQueue queue(1);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor(), &queue);
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    auto hello_ans = co_await read_packet(s);
    EXPECT_EQ(hello_ans.opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::STARTUPLOADREQ, encode_start_upload(f.hash));
    auto ans = co_await read_packet(s);
    EXPECT_EQ(ans.opcode, op::ACCEPTUPLOADREQ);
    s.close();
    co_return;
  });
  EXPECT_EQ(db.request_count(f.hash), 1u);
}

TEST(UploadSession, QueuesStartUploadWhenSlotsAreFull){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "queued.bin";
  f.size = 1;
  db.add(f);
  UploadQueue queue(1);
  queue.enqueue(*UserHash::from_hex("ffffffffffffffffffffffffffffffff"), f.hash);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor(), &queue);
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    auto hello_ans = co_await read_packet(s);
    EXPECT_EQ(hello_ans.opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::STARTUPLOADREQ, encode_start_upload(f.hash));
    auto ans = co_await read_packet(s);
    EXPECT_EQ(ans.opcode, op::QUEUERANKING);
    auto rank = decode_queue_ranking(ans.payload);
    EXPECT_TRUE(rank.has_value());
    if(!rank) co_return;
    EXPECT_EQ(*rank, 1u);
    s.close();
    co_return;
  });
}

TEST(UploadSession, AcceptsQueuedPeerAfterSlotReleaseOnReask){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "queued.bin";
  f.size = 1;
  db.add(f);
  UploadQueue queue(1);

  tcp::acceptor acceptor(rt.context(), tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  const auto port = acceptor.local_endpoint().port();
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
    for(int i = 0; i < 2; ++i) {
      auto [ec, sock] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      asio::co_spawn(rt.context(), [&, s = std::move(sock)]() mutable -> asio::awaitable<void>{
        UploadSession session(std::move(s), db, hello("server"), rt.disk_executor(), &queue);
        (void)co_await session.run(2s);
        co_return;
      }, asio::detached);
    }
    co_return;
  }, asio::detached);

  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c1(rt.executor());
    auto cr1 = co_await c1.connect(*IPv4::from_dotted("127.0.0.1"), port, 2s);
    EXPECT_TRUE(cr1.has_value()); if(!cr1) co_return;
    auto hs1 = co_await c1.handshake(hello_with_hash("client-1", "11111111111111111111111111111111"), 2s);
    EXPECT_TRUE(hs1.has_value()); if(!hs1) co_return;
    auto up1 = co_await c1.start_upload(f.hash, 2s);
    EXPECT_TRUE(up1.has_value()); if(!up1) co_return;

    C2CConnection c2(rt.executor());
    auto cr2 = co_await c2.connect(*IPv4::from_dotted("127.0.0.1"), port, 2s);
    EXPECT_TRUE(cr2.has_value()); if(!cr2) co_return;
    auto hs2 = co_await c2.handshake(hello_with_hash("client-2", "22222222222222222222222222222222"), 2s);
    EXPECT_TRUE(hs2.has_value()); if(!hs2) co_return;
    auto queued = co_await c2.start_upload(f.hash, 2s);
    EXPECT_FALSE(queued.has_value());
    if(queued) co_return;
    EXPECT_EQ(queued.error(), make_error_code(errc::upload_queued));

    c1.close();
    asio::steady_timer t(rt.context());
    t.expires_after(20ms);
    co_await t.async_wait(asio::use_awaitable);

    auto accepted = co_await c2.start_upload(f.hash, 2s);
    EXPECT_TRUE(accepted.has_value());
    c2.close();
    co_return;
  });
}

TEST(UploadSession, ThrottlesSendingPartFrames){
  ed2k::net::IoRuntime rt;
  auto data = sample_data(12000);
  auto path = temp_file("ed2k-upload-session-throttled.bin");
  write_file(path, data);
  KnownFileDB db;
  auto f = known_file_for(path, data);
  db.add(f);
  UploadBandwidthThrottler throttler(rt.executor(), 512000);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor(), nullptr, &throttler);
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto hs = co_await c.handshake(hello_without_compression("client"), 2s);
    EXPECT_TRUE(hs.has_value()); if(!hs) co_return;

    auto start = std::chrono::steady_clock::now();
    auto blocks = co_await c.request_blocks(f.hash, {0,0,0}, {12000,0,0}, 2s);
    auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_TRUE(blocks.has_value()); if(!blocks) co_return;
    EXPECT_GE(elapsed, 10ms);
    c.close();
    co_return;
  });
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(UploadSession, AccountsUploadedBytesAfterSendingPart){
  ed2k::net::IoRuntime rt;
  auto data = sample_data(1000);
  auto path = temp_file("ed2k-upload-session-credits.bin");
  write_file(path, data);
  KnownFileDB db;
  auto f = known_file_for(path, data);
  db.add(f);
  ClientCredits credits;
  const auto client_hash = *UserHash::from_hex("11111111111111111111111111111111");

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor(), nullptr, nullptr, &credits);
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto hs = co_await c.handshake(hello_with_hash("client", "11111111111111111111111111111111"), 2s);
    EXPECT_TRUE(hs.has_value()); if(!hs) co_return;
    auto blocks = co_await c.request_blocks(f.hash, {100,0,0}, {600,0,0}, 2s);
    EXPECT_TRUE(blocks.has_value()); if(!blocks) co_return;
    c.close();
    co_return;
  });
  EXPECT_EQ(credits.uploaded(client_hash), 500u);
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(UploadSession, AnswersAskSharedFiles){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "shared.bin";
  f.size = 1;
  db.add(f);

  auto self = hello("server");
  self.client_id = 0x0100007Fu;
  self.port = 4662;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, self, rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    EXPECT_EQ((co_await read_packet(s)).opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::ASKSHAREDFILES, {});
    auto ans = co_await read_packet(s);
    EXPECT_EQ(ans.opcode, op::ASKSHAREDFILESANSWER);
    auto decoded = decode_shared_files_answer(ans.payload);
    EXPECT_TRUE(decoded.has_value()); if(!decoded) co_return;
    EXPECT_EQ(decoded->size(), 1u);
    if(decoded->size() != 1u) co_return;
    EXPECT_EQ((*decoded)[0].hash, f.hash);
    EXPECT_EQ((*decoded)[0].client_id, self.client_id);
    EXPECT_EQ((*decoded)[0].port, self.port);
    s.close();
    co_return;
  });
}

TEST(UploadSession, AnswersRequestSources2WithEmptySourceList){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "shared.bin";
  f.size = 1;
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    EXPECT_EQ((co_await read_packet(s)).opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::REQUESTSOURCES2, encode_request_sources2(f.hash), ed2k::net::proto::eMule);
    auto ans = co_await read_packet(s);
    EXPECT_EQ(ans.protocol, ed2k::net::proto::eMule);
    EXPECT_EQ(ans.opcode, op::ANSWERSOURCES2);
    auto decoded = decode_answer_sources2(ans.payload);
    EXPECT_TRUE(decoded.has_value()); if(!decoded) co_return;
    EXPECT_EQ(decoded->hash, f.hash);
    EXPECT_TRUE(decoded->sources.empty());
    s.close();
    co_return;
  });
}

TEST(UploadSession, AnswersRequestSources2WithKnownSources){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "shared.bin";
  f.size = 1;
  f.sources.push_back({
    0x0100007Fu,
    4662,
    0x0200007Fu,
    4661,
    *UserHash::from_hex("11111111111111111111111111111111"),
    0x03
  });
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    EXPECT_EQ((co_await read_packet(s)).opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::REQUESTSOURCES2, encode_request_sources2(f.hash), ed2k::net::proto::eMule);
    auto ans = co_await read_packet(s);
    EXPECT_EQ(ans.protocol, ed2k::net::proto::eMule);
    EXPECT_EQ(ans.opcode, op::ANSWERSOURCES2);
    auto decoded = decode_answer_sources2(ans.payload);
    EXPECT_TRUE(decoded.has_value()); if(!decoded) co_return;
    EXPECT_EQ(decoded->hash, f.hash);
    EXPECT_EQ(decoded->sources.size(), 1u);
    if(decoded->sources.size() != 1u) co_return;
    EXPECT_EQ(decoded->sources[0].client_id, 0x0100007Fu);
    EXPECT_EQ(decoded->sources[0].port, 4662u);
    EXPECT_EQ(decoded->sources[0].server_ip, 0x0200007Fu);
    EXPECT_EQ(decoded->sources[0].server_port, 4661u);
    EXPECT_EQ(decoded->sources[0].user_hash, *UserHash::from_hex("11111111111111111111111111111111"));
    EXPECT_EQ(decoded->sources[0].crypt_options, 0x03u);
    s.close();
    co_return;
  });
}

TEST(UploadSession, AnswersMultipacketRequestSources2WithKnownSources){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "shared.bin";
  f.size = 1;
  f.sources.push_back({
    0x0100007Fu,
    4662,
    0x0200007Fu,
    4661,
    *UserHash::from_hex("11111111111111111111111111111111"),
    0x03
  });
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    EXPECT_EQ((co_await read_packet(s)).opcode, op::HELLOANSWER);

    ed2k::codec::ByteWriter req;
    req.hash16(f.hash);
    req.u8(op::REQUESTSOURCES2);
    req.u8(4);
    req.u16(0);
    co_await send_pkt(s, 0x92, req.take(), ed2k::net::proto::eMule);

    auto ans = co_await read_packet(s);
    EXPECT_EQ(ans.protocol, ed2k::net::proto::eMule);
    EXPECT_EQ(ans.opcode, op::ANSWERSOURCES2);
    auto decoded = decode_answer_sources2(ans.payload);
    EXPECT_TRUE(decoded.has_value()); if(!decoded) co_return;
    EXPECT_EQ(decoded->hash, f.hash);
    EXPECT_EQ(decoded->sources.size(), 1u);
    if(decoded->sources.size() != 1u) co_return;
    EXPECT_EQ(decoded->sources[0].client_id, 0x0100007Fu);
    EXPECT_EQ(decoded->sources[0].port, 4662u);
    EXPECT_EQ(decoded->sources[0].user_hash, *UserHash::from_hex("11111111111111111111111111111111"));
    s.close();
    co_return;
  });
}

TEST(UploadSession, AnswersPreviewRequestWithFirstFrame){
  net::IoRuntime rt;
  auto path = temp_file("ed2k_upload_preview.bin");
  auto data = sample_data(300 * 1024);
  write_file(path, data);

  KnownFileDB db;
  KnownFile f = known_file_for(path, data);
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    auto hello_ans = co_await read_packet(s);
    EXPECT_EQ(hello_ans.opcode, op::HELLOANSWER);

    co_await send_pkt(s, op::REQUESTPREVIEW, encode_preview_request(f.hash), ed2k::net::proto::eMule);
    auto ans = co_await read_packet(s);
    EXPECT_EQ(ans.protocol, ed2k::net::proto::eMule);
    EXPECT_EQ(ans.opcode, op::PREVIEWANSWER);
    auto preview = decode_preview_answer(ans.payload);
    EXPECT_TRUE(preview.has_value()) << (preview ? "" : preview.error().message());
    if(!preview) co_return;
    EXPECT_EQ(preview->hash, f.hash);
    EXPECT_EQ(preview->frames.size(), 1u);
    if(preview->frames.size() != 1u) co_return;
    EXPECT_EQ(preview->frames[0].size(), 256u * 1024u);
    EXPECT_EQ(preview->frames[0][0], data[0]);
    boost::system::error_code ignored; s.close(ignored);
    co_return;
  });
  std::filesystem::remove(path);
}

TEST(UploadSession, StoresFileDescForCurrentRequestedFile){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "shared.bin";
  f.size = 1;
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"), rt.disk_executor());
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    tcp::socket s(rt.context());
    auto [ec] = co_await s.async_connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), peer.port()), asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec); if(ec) co_return;
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
    EXPECT_EQ((co_await read_packet(s)).opcode, op::HELLOANSWER);
    co_await send_pkt(s, op::SETREQFILEID, encode_set_req_file(f.hash));
    EXPECT_EQ((co_await read_packet(s)).opcode, op::FILESTATUS);
    co_await send_pkt(s, op::FILEDESC, encode_file_desc(4, "verified source"));
    asio::steady_timer timer(rt.context());
    for(int i = 0; i < 20; ++i) {
      if(const auto* updated = db.find(f.hash); updated && updated->comment == "verified source") break;
      timer.expires_after(10ms);
      co_await timer.async_wait(asio::use_awaitable);
    }
    boost::system::error_code ignored;
    s.shutdown(tcp::socket::shutdown_send, ignored);
    co_return;
  });

  const auto* updated = db.find(f.hash);
  ASSERT_NE(updated, nullptr);
  EXPECT_EQ(updated->rating, 4u);
  EXPECT_EQ(updated->comment, "verified source");
}
