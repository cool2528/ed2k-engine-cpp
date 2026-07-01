#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <utility>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/server/connection.hpp"
#include "ed2k/server/opcodes.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "crypto/md4.hpp"
#include "crypto/sha1.hpp"
#include "ed2k/util/error.hpp"
#include "mock_peer.hpp"
#include "mock_server.hpp"
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
// IDCHANGE payload = u32 client_id + u32 flags（对照 server_connection_test 同名 helper）
static std::vector<std::byte> idchange_payload(std::uint32_t id, std::uint32_t flags){
  codec::ByteWriter w; w.u32(id); w.u32(flags); return w.take();
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
// read_frame 丢弃 5 字节头但保留 opcode 作为 body 首字节; read_pkt 进一步拆出
// (opcode, payload) 便于 MockServer 按 opcode 分派(如 CALLBACKREQUEST)。空帧(EOF/错)→ {0,{}}。
static asio::awaitable<std::pair<std::uint8_t,std::vector<std::byte>>> read_pkt(tcp::socket& s){
  auto body = co_await read_frame(s);
  if(body.empty()) co_return std::pair<std::uint8_t,std::vector<std::byte>>{0u, std::vector<std::byte>{}};
  std::uint8_t opcode = std::to_integer<std::uint8_t>(body[0]);
  std::vector<std::byte> rest(body.begin()+1, body.end());
  co_return std::pair<std::uint8_t,std::vector<std::byte>>{opcode, std::move(rest)};
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
// 参数化重载: 服务指定 full 数据 + hashset(M3 LowID 回调路径与多源测试复用)。
// 分派与 serve_full_peer(MockFile) 同款: HELLOANSWER/FILESTATUS/HASHSETANSWER/
// FILENAMEANSWER/ACCEPTUPLOADREQ/SENDINGPART + OUTOFPARTREQS 终止多响应循环。
static asio::awaitable<void> serve_full_peer(tcp::socket s, const std::vector<std::byte>& full,
                                             const FileHash& fhash, const std::vector<PartHash>& parts){
  using namespace ed2k::peer;
  (void)co_await read_frame(s);                          // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  (void)co_await read_frame(s);                          // SETREQFILEID
  { codec::ByteWriter w; w.hash16(fhash);
    w.u16(static_cast<std::uint16_t>(parts.size()));
    std::size_t nbytes = (parts.size() + 7) / 8;
    for(std::size_t i=0;i<nbytes;++i) w.u8(0xFF);        // 所有 part 均可用
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);                          // HASHSETREQUEST
  { codec::ByteWriter w; w.u16(static_cast<std::uint16_t>(parts.size()));
    for(const auto& p : parts) w.hash16(p);
    co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
  (void)co_await read_frame(s);                          // REQUESTFILENAME
  { codec::ByteWriter w; w.hash16(fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
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
    std::size_t off = static_cast<std::size_t>(s0);
    std::size_t len = static_cast<std::size_t>(e0 - s0);
    codec::ByteWriter w; w.hash16(fhash); w.u32(s0); w.u32(e0);
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
  // peer_worker exhausts same-peer retries -> block_corrupt. Then peer B (clean)
  // resumes from the on-disk PartFile and completes the file.
  //
  // C2 isolation: peer A and peer B run as two separate single-source downloads
  // against the SAME on-disk path so the disk can be inspected between peers.
  // After peer A fails, the corrupted block 5 region (uniform 0xFF from
  // serve_aich_peer) must NOT be on disk — verify-before-write (C2) prevented the
  // bad data from being persisted. After peer B completes, that region must equal
  // the correct file bytes — proving the corrupt data never survived.
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_aich"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  std::filesystem::remove(path);   // 从干净盘开始(隔离上次运行残留)
  auto mf = make_mock_file(0x11, 0x22);
  // C1: root 来自生产 hasher aich_hash_bytes(整文件), 与 AICHChecker::verify_block 的
  // flat 单层 Merkle 完全一致 —— 不再用任何 part-respecting 合成根。
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  AICHHash root = aich_hash_bytes(full);

  // 被损坏的 flat 块索引 5: 字节区 [5*AICH_BLOCK_SIZE, 6*AICH_BLOCK_SIZE)。
  constexpr std::size_t corrupt_blk = 5;
  const std::size_t corrupt_off = corrupt_blk * AICH_BLOCK_SIZE;

  IoRuntime rt;
  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_aich_peer(std::move(s), mf, true, corrupt_blk); co_return; });
  ed2k::test::MockPeer peerB(rt.context());
  peerB.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_aich_peer(std::move(s), mf, false); co_return; });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    // Phase 1: peer A 单源 —— 块 5 持续供坏数据 -> 同源重试耗尽 -> block_corrupt。
    download::MultiSourceDownload dlA(rt.executor(), path, mf.fhash, PART*2, std::optional<AICHHash>(root),
      std::vector{SourceEndpoint{0x7F000001u, peerA.port()}});
    auto rA = co_await dlA.run(10s, 3);
    EXPECT_FALSE(rA.has_value());
    if(rA.has_value()) co_return;
    EXPECT_EQ(rA.error(), make_error_code(errc::block_corrupt));

    // C2 (between peers): peer A 的坏块 5 (uniform 0xFF) 必须从未落盘 —— 先验证后写入生效。
    // 块 5 未写 -> 区间为洞(零); 若 C2 失效(先写后校验) -> 区间为全 0xFF, std::equal 命中 ->
    // EXPECT_FALSE 失败 -> 暴露 C2 回归。
    {
      std::ifstream f(path, std::ios::binary);
      EXPECT_TRUE(f.is_open());
      if(!f.is_open()) co_return;
      std::vector<std::byte> buf(AICH_BLOCK_SIZE);
      f.seekg(static_cast<std::streamoff>(corrupt_off));
      f.read(reinterpret_cast<char*>(buf.data()), AICH_BLOCK_SIZE);
      EXPECT_EQ(static_cast<std::size_t>(f.gcount()), AICH_BLOCK_SIZE);
      if(static_cast<std::size_t>(f.gcount()) != AICH_BLOCK_SIZE) co_return;
      std::vector<std::byte> corrupt_fill(AICH_BLOCK_SIZE, std::byte(0xFF));
      EXPECT_FALSE(std::equal(buf.begin(), buf.end(), corrupt_fill.begin()))
        << "peer A persisted corrupt 0xFF block to disk before AICH verify (C2 broken)";
    }

    // Phase 2: peer B (clean) —— 从盘上 PartFile 恢复, 补齐块 5 及其余, 完成文件。
    download::MultiSourceDownload dlB(rt.executor(), path, mf.fhash, PART*2, std::optional<AICHHash>(root),
      std::vector{SourceEndpoint{0x7F000001u, peerB.port()}});
    auto rB = co_await dlB.run(10s, 3);
    EXPECT_TRUE(rB.has_value()); if(!rB) co_return;

    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());

    // C2 (after completion): 块 5 区间最终等于正确文件数据 -> 坏数据从未存活。
    {
      std::ifstream f(path, std::ios::binary);
      EXPECT_TRUE(f.is_open());
      if(!f.is_open()) co_return;
      std::vector<std::byte> buf(AICH_BLOCK_SIZE);
      f.seekg(static_cast<std::streamoff>(corrupt_off));
      f.read(reinterpret_cast<char*>(buf.data()), AICH_BLOCK_SIZE);
      EXPECT_EQ(static_cast<std::size_t>(f.gcount()), AICH_BLOCK_SIZE);
      if(static_cast<std::size_t>(f.gcount()) != AICH_BLOCK_SIZE) co_return;
      auto expect = std::span<const std::byte>(full).subspan(corrupt_off, AICH_BLOCK_SIZE);
      EXPECT_TRUE(std::equal(buf.begin(), buf.end(), expect.begin()))
        << "final block 5 bytes do not match the correct file data";
    }
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

TEST(Download, LowIdSourceViaCallback){
  // M3 capstone: LowID source via server callback. MockServer 登录后读到客户端发来的
  // CALLBACKREQUEST(source.id=0x100), 即刻 spawn 一个 MockPeer 主动连 InboundListener
  // 端口并供文件; peer_worker LowID 分支:
  //   callback_request -> listener.accept -> C2CConnection(tcp::socket&&) -> handshake/下载。
  // HighID 直连路径不动, 此测试只覆盖 LowID 回调分支。
  auto mf = make_mock_file(0x33, 0x44);   // 2-part
  std::vector<std::byte> full;
  full.insert(full.end(), mf.d0.begin(), mf.d0.end());
  full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  IoRuntime rt;
  ed2k::peer::InboundListener lst(rt.executor(), 0);   // 临时端口
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    co_await send_pkt(s, server::op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    // 读到 CALLBACKREQUEST 一帧即触发回调 peer 主动连 listener(修正说明 #2: 用 read_pkt 保留 opcode)
    auto [opcode, payload] = co_await read_pkt(s);
    (void)payload;
    if(opcode != server::op::CALLBACKREQUEST){ co_return; }
    asio::co_spawn(s.get_executor(), [&,kk=lst.local_port()]() -> asio::awaitable<void>{
      tcp::socket c(s.get_executor());
      tcp::endpoint ep(asio::ip::make_address_v4("127.0.0.1"), kk);
      auto [ec] = co_await c.async_connect(ep, asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      co_await serve_full_peer(std::move(c), full, mf.fhash, {mf.h0, mf.h1});
      co_return;
    }, asio::detached);
    co_await keep_alive(s); co_return;
  });
  auto tmp = std::filesystem::temp_directory_path()/"ed2k_lowid_cb"; std::filesystem::remove(tmp);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    // 用真实 ServerConnection 登录到 mock srv, 取得 server_conn(LowID 回调路径需要)
    server::ServerConnection sc(rt.executor());
    server::LoginParams p; p.nickname="u"; p.client_port=lst.local_port();
    p.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
    auto lr = co_await sc.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 3000ms);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;
    // LowID 源: id=0x100(<0x1000000), port=0(回调路径不用 port)
    std::vector<server::SourceEndpoint> srcs = { {0x100u, 0} };
    MultiSourceDownload dl(rt.executor(), tmp, mf.fhash, PART*2, std::nullopt, srcs, &sc, &lst);
    auto r = co_await dl.run(20000ms, 3);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    co_return;
  });
  ASSERT_TRUE(std::filesystem::exists(tmp));
  EXPECT_EQ(std::filesystem::file_size(tmp), PART*2);
  std::filesystem::remove(tmp);
}

TEST(Download, RequestPartsI64RoundTrip){
  // test I64 encoding works
  // Already covered by c2c_messages_test
  GTEST_SKIP() << "I64 encoding covered by C2CMessages tests";
}
