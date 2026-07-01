#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "crypto/md4.hpp"
#include "crypto/sha1.hpp"
#include "ed2k/util/error.hpp"
#include "mock_peer.hpp"
using namespace ed2k; using namespace ed2k::net; using namespace ed2k::peer;
using namespace ed2k::download;
using ed2k::server::SourceEndpoint;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;
static constexpr std::uint64_t PART = 9728000;
template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}
static std::vector<std::byte> bytes(std::initializer_list<int> xs){
  std::vector<std::byte> v; for(int x:xs) v.push_back(std::byte(x)); return v;
}
static asio::awaitable<void> send_pkt(tcp::socket& s, std::uint8_t op, std::span<const std::byte> pl){
  Packet p; p.protocol=proto::eDonkey; p.opcode=op; p.payload.assign(pl.begin(),pl.end());
  auto fr=encode_frame(p); auto [e,n]=co_await asio::async_write(s,asio::buffer(fr),asio::as_tuple(asio::use_awaitable)); (void)e;(void)n; co_return;
}
static asio::awaitable<std::vector<std::byte>> read_frame(tcp::socket& s){
  std::array<std::byte,5> hdr; auto [e1,n1]=co_await asio::async_read(s,asio::buffer(hdr),asio::as_tuple(asio::use_awaitable)); (void)n1;
  if(e1) co_return std::vector<std::byte>{};
  auto h=parse_header(hdr); if(!h) co_return std::vector<std::byte>{};
  std::vector<std::byte> body(h->size); auto [e2,n2]=co_await asio::async_read(s,asio::buffer(body),asio::as_tuple(asio::use_awaitable)); (void)n2;
  if(e2) co_return std::vector<std::byte>{};
  co_return body;
}
static asio::awaitable<void> keep_alive(tcp::socket& s){ std::array<std::byte,1> t; auto [e,n]=co_await asio::async_read(s,asio::buffer(t),asio::as_tuple(asio::use_awaitable)); (void)e;(void)n; co_return; }
// mock peer 提供一个 2-part 文件,part 数据由 fill 决定
struct MockFile { std::vector<std::byte> d0, d1; PartHash h0, h1; FileHash fhash; };
static MockFile make_mock_file(std::uint8_t f0, std::uint8_t f1){
  MockFile mf;
  mf.d0.assign(PART, std::byte(f0)); mf.d1.assign(PART, std::byte(f1));
  crypto::MD4 m; m.update(mf.d0); mf.h0 = PartHash::from_bytes(m.finish());
  m = {}; m.update(mf.d1); mf.h1 = PartHash::from_bytes(m.finish());
  // file hash = MD4(h0 || h1)
  m = {}; m.update(mf.h0.bytes()); m.update(mf.h1.bytes()); mf.fhash = FileHash::from_bytes(m.finish());
  return mf;
}
// FLAT whole-file AICH leaf computation: 184320-B blocks from offset 0, matching
// aich_hash_bytes and AICHChecker::verify_block exactly. Leaves MAY span part
// boundaries (PART_SIZE=9728000 is not a multiple of AICH_BLOCK_SIZE=184320:
// 9728000/184320=52.777), so the flat single-layer Merkle tree differs from any
// per-part decomposition. The download path (PartFile/BlockAllocator/peer_worker)
// now uses the same flat blocks, so aich_hash_bytes(file) is the verifiable root.
static std::vector<std::array<std::byte,20>> compute_flat_leaves(const std::vector<std::byte>& full){
  std::vector<std::array<std::byte,20>> leaves;
  std::size_t off=0, n=full.size();
  while(off < n){
    std::size_t take = std::min(static_cast<std::size_t>(AICH_BLOCK_SIZE), n-off);
    leaves.push_back(crypto::sha1(std::span<const std::byte>(full).subspan(off, take)));
    off += take;
  }
  return leaves;
}
// lone-child Merkle proof path for flat leaf `idx` in a tree of `leaves`.
// Sibling omitted on lone layers (sibling >= level.size), matching verify_block.
static std::vector<std::array<std::byte,20>> compute_flat_proof(std::size_t idx, std::vector<std::array<std::byte,20>> leaves){
  std::vector<std::array<std::byte,20>> path;
  std::size_t i = idx;
  while(leaves.size() > 1){
    std::size_t sib = i ^ 1;
    if(sib < leaves.size()) path.push_back(leaves[sib]);
    std::vector<std::array<std::byte,20>> nxt;
    for(std::size_t k = 0; k < leaves.size(); k += 2){
      if(k+1 < leaves.size()){
        std::array<std::byte,40> b;
        for(int t=0;t<20;++t){ b[t]=leaves[k][t]; b[20+t]=leaves[k+1][t]; }
        nxt.push_back(crypto::sha1(b));
      } else {
        nxt.push_back(leaves[k]);
      }
    }
    leaves.swap(nxt); i /= 2;
  }
  return path;
}
// peer 响应 Download 的请求序列:HELLO→FILESTATUS→HASHSET→FILENAME→ACCEPT→
// 循环处理 REQUESTPARTS:解析请求范围,回送对应字节切片 + OUTOFPARTREQS 终止多响应循环。
// 请求范围 [s0,e0) 是 flat 整文件块, 可能跨越 part 边界: 从 full=d0||d1 切片即可。
static asio::awaitable<void> serve_full_peer(tcp::socket s, const MockFile& mf){
  using namespace ed2k::peer;
  std::vector<std::byte> full;
  full.insert(full.end(), mf.d0.begin(), mf.d0.end());
  full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  (void)co_await read_frame(s);                          // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  (void)co_await read_frame(s);                          // SETREQFILEID
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u16(2); w.u8(0xFF); w.u8(0x03);  // 两 part 都有
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);                          // HASHSETREQUEST
  { codec::ByteWriter w; w.u16(2); w.hash16(mf.h0); w.hash16(mf.h1);
    co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
  (void)co_await read_frame(s);                          // REQUESTFILENAME
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
    co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
  (void)co_await read_frame(s); co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});  // STARTUPLOADREQ
  for(;;){
    auto body = co_await read_frame(s);                  // REQUESTPARTS
    if(body.empty()){ co_await keep_alive(s); co_return; }
    codec::ByteReader r(std::span<const std::byte>(body).subspan(1));  // 跳过 opcode
    (void)r.hash16();                                    // 文件 hash
    std::uint32_t s0=r.u32(), s1=r.u32(), s2=r.u32();
    std::uint32_t e0=r.u32(), e1=r.u32(), e2=r.u32();
    (void)s1;(void)s2;(void)e1;(void)e2;
    if(s0==0 && e0==0){ co_await keep_alive(s); co_return; }
    // flat 切片: [s0,e0) 可能跨 part 边界, 直接从 full 取
    std::size_t off = static_cast<std::size_t>(s0);
    std::size_t len = static_cast<std::size_t>(e0 - s0);
    codec::ByteWriter w; w.hash16(mf.fhash); w.u32(s0); w.u32(e0);
    w.blob(std::span<const std::byte>(full).subspan(off, len));
    co_await send_pkt(s, op::SENDINGPART, w.take());
    co_await send_pkt(s, op::OUTOFPARTREQS, {});         // 终止 request_blocks 多响应循环
  }
  co_await keep_alive(s); co_return;
}
// AICH-aware mock peer: like serve_full_peer but also answers AICHREQUEST with a
// correct FLAT lone-child Merkle proof path over the whole file. Proof is always
// computed from the CLEAN full file; data corruption (corrupt_block_n) only affects
// SENDINGPART, so verify_block fails on tampered data while the proof stays valid.
static asio::awaitable<void> serve_aich_peer(tcp::socket s, const MockFile& mf, bool corrupt_block_n = false, std::size_t corrupt_idx = 0){
  using namespace ed2k::peer;
  (void)co_await read_frame(s);   // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  (void)co_await read_frame(s);   // SETREQFILEID
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u16(2); w.u8(0xFF); w.u8(0x03);
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);   // HASHSETREQUEST
  { codec::ByteWriter w; w.u16(2); w.hash16(mf.h0); w.hash16(mf.h1);
    co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
  (void)co_await read_frame(s);   // REQUESTFILENAME
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
    co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
  (void)co_await read_frame(s); co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});  // STARTUPLOADREQ

  // Build full file + FLAT AICH leaves (whole-file 184320-B blocks, matching
  // aich_hash_bytes and AICHChecker::verify_block; leaves may span part boundaries).
  std::vector<std::byte> full;
  full.insert(full.end(), mf.d0.begin(), mf.d0.end());
  full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  auto leaves = compute_flat_leaves(full);

  for(;;){
    auto body = co_await read_frame(s);
    if(body.empty()){ co_await keep_alive(s); co_return; }
    std::uint8_t opcode = std::to_integer<std::uint8_t>(body[0]);
    std::span<const std::byte> pl(body.data()+1, body.size()-1);
    if(opcode == op::AICHREQUEST){
      codec::ByteReader r(pl); (void)r.hash16();   // file hash (already validated by caller)
      std::uint16_t idx = r.u16();                  // flat global AICH block index
      auto path = compute_flat_proof(idx, leaves);
      codec::ByteWriter w; w.hash16(mf.fhash); w.u16(static_cast<std::uint16_t>(path.size()));
      for(auto& h : path){ w.blob(std::span<const std::byte>(h)); }
      co_await send_pkt(s, op::AICHANSWER, w.take());
      continue;
    }
    if(opcode == op::REQUESTPARTS){
      codec::ByteReader r(pl); (void)r.hash16();
      std::uint32_t s0=r.u32(), s1=r.u32(), s2=r.u32(), e0=r.u32(), e1=r.u32(), e2=r.u32();
      (void)s1;(void)s2;(void)e1;(void)e2;
      if(s0==0 && e0==0){ co_await keep_alive(s); co_return; }
      std::size_t off = s0;
      std::size_t len = e0 - s0;
      std::vector<std::byte> d(full.begin()+off, full.begin()+off+len);
      if(corrupt_block_n){
        // corrupt_idx is the flat global block index (s0/AICH_BLOCK_SIZE == global).
        std::size_t blkidx = s0 / AICH_BLOCK_SIZE;
        if(blkidx == corrupt_idx) std::fill(d.begin(), d.end(), std::byte(0xFF));
      }
      codec::ByteWriter w; w.hash16(mf.fhash); w.u32(s0); w.u32(e0); w.blob(std::span<const std::byte>(d));
      co_await send_pkt(s, op::SENDINGPART, w.take());
      co_await send_pkt(s, op::OUTOFPARTREQS, {});
      continue;
    }
    // other opcodes ignored
  }
  co_await keep_alive(s); co_return;
}
TEST(Download, EndToEndSingleSource){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_e2e"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x7F000001u, peer.port()});
    auto r = co_await dl.run(5s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    // 校验文件
    { PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1}); EXPECT_TRUE(pf.complete()); }
    co_return;
  });
  std::filesystem::remove_all(dir);
}
TEST(Download, ResumeSkipsCompletedParts){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_resume"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  // 预写 part0
  { std::ofstream f(path, std::ios::binary); f.write(reinterpret_cast<const char*>(mf.d0.data()), mf.d0.size()); }
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x7F000001u, peer.port()});
    auto r = co_await dl.run(5s);
    EXPECT_TRUE(r.has_value());                          // part0 已校验跳过,只下 part1
    co_return;
  });
  std::filesystem::remove_all(dir);
}
TEST(Download, BlockCorruptFails){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_corrupt"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  // peer 发坏 part0 数据(填充 0xFF,但 hashset 用正确 h0)
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    auto bad = mf; bad.d0.assign(PART, std::byte(0xFF));  // 坏数据
    co_await serve_full_peer(std::move(s), bad); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x7F000001u, peer.port()});
    auto r = co_await dl.run(5s);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::block_corrupt));
    co_return;
  });
  std::filesystem::remove_all(dir);
}

TEST(Download, BlockLevelSingleSource){
  // download 2-part file with block-level allocation (no AICH)
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_block"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), mf); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::MultiSourceDownload dl(rt.executor(), path, mf.fhash, PART*2, std::nullopt,
      std::vector{SourceEndpoint{0x7F000001u, peer.port()}});
    auto r = co_await dl.run(5s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  std::filesystem::remove_all(dir);
}

TEST(Download, AICHCorruptionRecovers){
  // Block-level AICH recovery: peer A always serves a corrupted flat block 5;
  // peer_worker exhausts same-peer retries -> block_corrupt -> MultiSourceDownload
  // switches to peer B which serves the clean block. File completes and verifies.
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_aich"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  // C1: root 来自生产 hasher aich_hash_bytes(整文件), 与 AICHChecker::verify_block 的
  // flat 单层 Merkle 完全一致 —— 不再用任何 part-respecting 合成根。
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  AICHHash root = aich_hash_bytes(full);

  IoRuntime rt;
  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_aich_peer(std::move(s), mf, true, 5); co_return; });
  ed2k::test::MockPeer peerB(rt.context());
  peerB.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_aich_peer(std::move(s), mf, false); co_return; });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::MultiSourceDownload dl(rt.executor(), path, mf.fhash, PART*2, std::optional<AICHHash>(root),
      std::vector{SourceEndpoint{0x7F000001u, peerA.port()}, SourceEndpoint{0x7F000001u, peerB.port()}});
    auto r = co_await dl.run(10s, 3);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  std::filesystem::remove_all(dir);
}

TEST(Download, BlockLevelAICHSingleSource){
  // AICH-enabled block-level download, single clean source -> file completes and verifies.
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_aich_ok"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  AICHHash root = aich_hash_bytes(full);
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_aich_peer(std::move(s), mf, false); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::MultiSourceDownload dl(rt.executor(), path, mf.fhash, PART*2, std::optional<AICHHash>(root),
      std::vector{SourceEndpoint{0x7F000001u, peer.port()}});
    auto r = co_await dl.run(10s, 3);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  std::filesystem::remove_all(dir);
}

TEST(Download, AICHWrongRootFails){
  // C1 mutation: 正确 root = aich_hash_bytes(full) 时下载通过; 翻转 root 后 verify_block
  // 拒绝每个块 -> 同源重试耗尽 -> block_corrupt -> 失败。证明 verify_block 是真校验而非桩。
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_aich_badroot"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  AICHHash good_root = aich_hash_bytes(full);
  auto bad_bytes = good_root.bytes(); bad_bytes[0] = bad_bytes[0] ^ std::byte(0x01);
  AICHHash bad_root = AICHHash::from_bytes(bad_bytes);
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_aich_peer(std::move(s), mf, false); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::MultiSourceDownload dl(rt.executor(), path, mf.fhash, PART*2, std::optional<AICHHash>(bad_root),
      std::vector{SourceEndpoint{0x7F000001u, peer.port()}});
    auto r = co_await dl.run(10s, 3);
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::block_corrupt));
    co_return;
  });
  std::filesystem::remove_all(dir);
}

TEST(Download, RequestPartsI64RoundTrip){
  // test I64 encoding works
  // Already covered by c2c_messages_test
  GTEST_SKIP() << "I64 encoding covered by C2CMessages tests";
}
