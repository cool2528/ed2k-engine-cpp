#include <gtest/gtest.h>
#include <array>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/download/aich_checker.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include "ed2k/share/known_file.hpp"
#include "ed2k/share/upload_session.hpp"
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

static std::filesystem::path temp_file(std::string name){
  return std::filesystem::temp_directory_path() / std::move(name);
}

static std::vector<std::byte> sample_data(std::size_t n){
  std::vector<std::byte> data(n);
  for(std::size_t i=0;i<n;++i) data[i]=std::byte((i*37u + 11u) & 0xFFu);
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
    co_await send_pkt(s, op::HELLO, encode_hello_packet(hello("client")));
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
