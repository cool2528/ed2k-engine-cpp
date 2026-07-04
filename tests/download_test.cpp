#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>
#include <utility>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/download/block_allocator.hpp"
#include "ed2k/metfile/known_part_met.hpp"
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
// === V2 两级 AICH 恢复数据生成 (对照 aMule SHAHashSet::CreatePartRecoveryData) ===
// 标识符: 根=1(不出现在 proof); 左子=(ident<<1)|1, 右子=ident<<1。左偏 split
//   nLeft=((is_left?nBlocks+1:nBlocks)/2)*base; 子 base=(nSide<=PART)?AICH_BLOCK_SIZE:PART。
// recovery_for(full, part) = (nLevel-1) 兄弟 part-root + 该 part 全部 L 叶, 各带标识符。
namespace {
using Digest = std::array<std::byte, 20>;
struct Split { std::uint64_t n_left, n_right, base_left, base_right; };
Split split_children(std::uint64_t n, std::uint64_t base, bool is_left) {
  std::uint64_t nBlocks = n / base + ((n % base) != 0 ? 1 : 0);
  std::uint64_t nLeft  = ((is_left ? nBlocks + 1 : nBlocks) / 2) * base;
  std::uint64_t nRight = n - nLeft;
  std::uint64_t bl = (nLeft  <= PART) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART;
  std::uint64_t br = (nRight <= PART) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART;
  return {nLeft, nRight, bl, br};
}
Digest sha1_cat(const Digest& l, const Digest& r) {
  crypto::SHA1 h; h.update(l); h.update(r); return h.finish();
}
// 子树根 (aich_hasher build_subtree 的独立复刻; 亦用于兄弟 part-root hash)。
Digest subtree_root(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left) {
  if (n <= base) return crypto::sha1(d.first(static_cast<std::size_t>(n)));
  auto s = split_children(n, base, is_left);
  return sha1_cat(subtree_root(d.first(static_cast<std::size_t>(s.n_left)),  s.n_left,  s.base_left,  true),
                  subtree_root(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false));
}
// WriteLowestLevelHashs 对偶: 收集子树所有叶 (ident, SHA1(叶数据)), 左→右序。
void collect_leaves(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left,
                    std::uint32_t ident, std::vector<AICHProofHash>& out) {
  if (n <= base) {
    AICHProofHash p; p.identifier = ident; p.hash = crypto::sha1(d.first(static_cast<std::size_t>(n)));
    out.push_back(p); return;
  }
  auto s = split_children(n, base, is_left);
  collect_leaves(d.first(static_cast<std::size_t>(s.n_left)),  s.n_left,  s.base_left,  true,  (ident << 1) | 1, out);
  collect_leaves(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false, ident << 1,       out);
}
// CreatePartRecoveryData 对偶: part_off/part_size = part 在当前节点数据内的 [偏移, 大小)。
void collect_recovery(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left,
                      std::uint32_t ident, std::uint64_t part_off, std::uint64_t part_size,
                      std::vector<AICHProofHash>& out) {
  if (part_off == 0 && part_size == n) { collect_leaves(d, n, base, is_left, ident, out); return; }
  auto s = split_children(n, base, is_left);
  std::uint32_t left_ident = (ident << 1) | 1, right_ident = ident << 1;
  if (part_off < s.n_left) {
    AICHProofHash p; p.identifier = right_ident;
    p.hash = subtree_root(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false);
    out.push_back(p);
    collect_recovery(d.first(static_cast<std::size_t>(s.n_left)), s.n_left, s.base_left, true,
                     left_ident, part_off, part_size, out);
  } else {
    AICHProofHash p; p.identifier = left_ident;
    p.hash = subtree_root(d.first(static_cast<std::size_t>(s.n_left)), s.n_left, s.base_left, true);
    out.push_back(p);
    collect_recovery(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false,
                     right_ident, part_off - s.n_left, part_size, out);
  }
}
std::vector<AICHProofHash> recovery_for(const std::vector<std::byte>& full, std::size_t part_index) {
  std::uint64_t n = full.size();
  std::uint64_t root_base = (n <= PART) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART;
  std::uint64_t pstart = static_cast<std::uint64_t>(part_index) * PART;
  std::uint64_t psize = std::min(PART, n - pstart);
  std::vector<AICHProofHash> out;
  collect_recovery(std::span<const std::byte>(full), n, root_base, true, 1, pstart, psize, out);
  return out;
}
}  // namespace
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
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u16(2); w.hash16(mf.h0); w.hash16(mf.h1);
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
  }
  co_await keep_alive(s); co_return;
}
// 参数化重载: 服务指定 full 数据 + hashset(M3 LowID 回调路径与多源测试复用)。
// 分派与 serve_full_peer(MockFile) 同款: HELLOANSWER/FILESTATUS/HASHSETANSWER/
// FILENAMEANSWER/ACCEPTUPLOADREQ/SENDINGPART + OUTOFPARTREQS 终止多响应循环。
// send_hello_first: 模拟 TCP 主动方(LowID 回调里拨入 listener 的源)——先发 HELLO 再等
// HELLOANSWER;默认 false = acceptor 模式(读 HELLO 回 HELLOANSWER),保持既有 HighID 调用不变。
static asio::awaitable<void> serve_full_peer(tcp::socket s, const std::vector<std::byte>& full,
                                             const FileHash& fhash, const std::vector<PartHash>& parts,
                                             bool send_hello_first = false){
  using namespace ed2k::peer;
  HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
  if(send_hello_first){
    // initiator: 先发 HELLO,再等对端(acceptor)回 HELLOANSWER。复用同一 HelloInfo。
    co_await send_pkt(s, op::HELLO, encode_hello_packet(h));
    (void)co_await read_frame(s);                        // HELLOANSWER
  } else {
    (void)co_await read_frame(s);                        // HELLO
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h));
  }
  (void)co_await read_frame(s);                          // SETREQFILEID
  { codec::ByteWriter w; w.hash16(fhash);
    w.u16(static_cast<std::uint16_t>(parts.size()));
    std::size_t nbytes = (parts.size() + 7) / 8;
    for(std::size_t i=0;i<nbytes;++i) w.u8(0xFF);        // 所有 part 均可用
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);                          // HASHSETREQUEST
  { codec::ByteWriter w; w.hash16(fhash); w.u16(static_cast<std::uint16_t>(parts.size()));
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
  }
  co_await keep_alive(s); co_return;
}
// AICH-aware mock peer (两级 V2): 回 OP_AICHFILEHASHANS(真实两级 master) + 对任意 part 回
// OP_AICHANSWER(V2 恢复数据 = 兄弟 part-root + 该 part 全部叶, 带标识符)。数据损坏
// (corrupt_block_n) 只影响 SENDINGPART —— proof 恒取自 clean full, 故 verify_block 对
// 篡改数据失败而对干净数据通过。
static asio::awaitable<void> serve_aich_peer(tcp::socket s, const MockFile& mf, bool corrupt_block_n = false, std::size_t corrupt_idx = 0){
  using namespace ed2k::peer;
  (void)co_await read_frame(s);   // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  (void)co_await read_frame(s);   // SETREQFILEID
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u16(2); w.u8(0xFF); w.u8(0x03);
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);   // HASHSETREQUEST
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u16(2); w.hash16(mf.h0); w.hash16(mf.h1);
    co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
  (void)co_await read_frame(s);   // REQUESTFILENAME
  { codec::ByteWriter w; w.hash16(mf.fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
    co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
  (void)co_await read_frame(s); co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});  // STARTUPLOADREQ

  // 两级 AICH root 取自 clean full (aich_hash_bytes); 损坏只作用于 SENDINGPART。
  std::vector<std::byte> full;
  full.insert(full.end(), mf.d0.begin(), mf.d0.end());
  full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  AICHHash master = aich_hash_bytes(full);
  // 预计算每 part 的 V2 恢复数据 (recovery_for 重算 53 叶 SHA1, 逐块重算会拖慢测试 ~50×);
  // peer 按 part_index 回送缓存, 与生产端 "part 级 proof" 语义一致 (一 part 一份恢复数据)。
  std::array<std::vector<AICHProofHash>, 2> rec_cache;
  rec_cache[0] = recovery_for(full, 0);
  rec_cache[1] = recovery_for(full, 1);

  for(;;){
    auto body = co_await read_frame(s);
    if(body.empty()){ co_await keep_alive(s); co_return; }
    std::uint8_t opcode = std::to_integer<std::uint8_t>(body[0]);
    std::span<const std::byte> pl(body.data()+1, body.size()-1);
    if(opcode == op::AICHFILEHASHREQ){
      // OP_AICHFILEHASHANS = file_hash(16) + master_hash(20)
      codec::ByteWriter w; w.hash16(mf.fhash); w.hash20(master.bytes());
      co_await send_pkt(s, op::AICHFILEHASHANS, w.take());
      continue;
    }
    if(opcode == op::AICHREQUEST){
      // 请求帧 = file_hash(16) + part_index(u16) + master_hash(20); 回显请求方 master_hash
      // (客户端 request_aich_proof 校验 echoed==requested)。V2 data = count16 + [ident16+hash]
      // + count32(=0, 非大文件路径)。
      codec::ByteReader r(pl); (void)r.hash16();
      std::uint16_t part_index = r.u16();
      auto echoed_master = r.hash20();
      if(part_index >= rec_cache.size()){ co_await keep_alive(s); co_return; }
      const auto& rec = rec_cache[part_index];
      codec::ByteWriter w; w.hash16(mf.fhash); w.u16(part_index); w.hash20(echoed_master);
      w.u16(static_cast<std::uint16_t>(rec.size()));
      for(const auto& p : rec){ w.u16(static_cast<std::uint16_t>(p.identifier)); w.hash20(p.hash); }
      w.u16(0);   // count32
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
        // corrupt_idx 为 part 内块号; part0 起始偏移 0 → s0/AICH_BLOCK_SIZE == part0 块号。
        // part1 块号 = (s0-PART)/AICH_BLOCK_SIZE, 不会等于 part0 的 corrupt_idx。
        std::size_t blkidx = s0 / AICH_BLOCK_SIZE;
        if(blkidx == corrupt_idx) std::fill(d.begin(), d.end(), std::byte(0xFF));
      }
      codec::ByteWriter w; w.hash16(mf.fhash); w.u32(s0); w.u32(e0); w.blob(std::span<const std::byte>(d));
      co_await send_pkt(s, op::SENDINGPART, w.take());
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
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x0100007Fu, peer.port()});
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
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x0100007Fu, peer.port()});
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
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x0100007Fu, peer.port()});
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
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peer.port()}}).build();
    auto r = co_await dl.run(5s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  std::filesystem::remove_all(dir);
}

// M4c 两级 per-part AICH 损坏恢复。client 可信根 = aich_hash_bytes(full); peer A 回匹配
// master(取自 clean full)但 SENDINGPART 对 part0 块5 供 0xFF → verify_block 叶校验失败 →
// 同源重试耗尽 → block_corrupt; peer B(clean) 续传完成。C2 先验证后写入: 块5 坏数据从未落盘。
TEST(Download, AICHCorruptionRecovers){
  // Block-level AICH recovery: peer A always serves a corrupted part0 block 5;
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
  // C1: root 来自生产 hasher aich_hash_bytes(整文件) —— 两级 Merkle 根, 与
  // AICHChecker::verify_block 的 rebuild==root 完全一致。
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  AICHHash root = aich_hash_bytes(full);

  // 被损坏的 part0 块5: 字节区 [5*AICH_BLOCK_SIZE, 6*AICH_BLOCK_SIZE)。
  constexpr std::size_t corrupt_blk = 5;
  const std::size_t corrupt_off = corrupt_blk * AICH_BLOCK_SIZE;

  IoRuntime rt;
  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_aich_peer(std::move(s), mf, true, corrupt_blk); co_return; });
  ed2k::test::MockPeer peerB(rt.context());
  peerB.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_aich_peer(std::move(s), mf, false); co_return; });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    // Phase 1: peer A 单源 —— 块5 持续供坏数据 -> 同源重试耗尽 -> block_corrupt。
    auto dlA = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::optional<AICHHash>(root))
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peerA.port()}}).build();
    auto rA = co_await dlA.run(15s, 3);
    EXPECT_FALSE(rA.has_value());
    if(rA.has_value()) co_return;
    EXPECT_EQ(rA.error(), make_error_code(errc::block_corrupt));

    // C2 (between peers): peer A 的坏块5 (uniform 0xFF) 必须从未落盘 —— 先验证后写入生效。
    // PartFile 不预分配(按 write_block 增长): 块5 未写 → 该区在 EOF(短读) → 绝非 0xFF;
    // 若 C2 失效(先写后校验) → 块5 = 全 0xFF (满读命中) -> is_corrupt=true -> 暴露 C2 回归。
    {
      std::ifstream f(path, std::ios::binary);
      EXPECT_TRUE(f.is_open());
      if(!f.is_open()) co_return;
      std::vector<std::byte> buf(AICH_BLOCK_SIZE, std::byte(0));
      f.seekg(static_cast<std::streamoff>(corrupt_off));
      f.read(reinterpret_cast<char*>(buf.data()), AICH_BLOCK_SIZE);
      auto got = static_cast<std::size_t>(f.gcount());
      std::vector<std::byte> corrupt_fill(AICH_BLOCK_SIZE, std::byte(0xFF));
      bool is_corrupt = (got == AICH_BLOCK_SIZE) && std::equal(buf.begin(), buf.end(), corrupt_fill.begin());
      EXPECT_FALSE(is_corrupt) << "peer A persisted corrupt 0xFF block 5 before AICH verify (C2 broken)";
    }

    // Phase 2: peer B (clean) —— 从盘上 PartFile 恢复, 补齐块5 及其余, 完成文件。
    auto dlB = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::optional<AICHHash>(root))
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peerB.port()}}).build();
    auto rB = co_await dlB.run(15s, 3);
    EXPECT_TRUE(rB.has_value()); if(!rB) co_return;

    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());

    // C2 (after completion): 块5 区间最终等于正确文件数据 -> 坏数据从未存活。
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

// M4c 两级 per-part AICH 单源下载: client 可信根 = aich_hash_bytes(full), peer 回匹配
// master + 正确 V2 恢复数据 → master 协商通过 → AICH 启用 → 逐块 verify 通过 → 完成。
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
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::optional<AICHHash>(root))
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peer.port()}}).build();
    auto r = co_await dl.run(15s, 3);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  std::filesystem::remove_all(dir);
}

// M4c master-hash 协商降级: client 可信根为错误 root(bad_root), peer 回正确 master(good_root)
// → 不匹配 → 降级为无 AICH 下载 → peer 供正确数据 → 完成。成功即证明降级生效: 若未降级
// (AICH 仍以 bad_root 启用), verify_block 对每块 rebuild!=bad_root 失败 → block_corrupt → 失败。
// (verify_block 真校验本身由 AICHCorruptionRecovers 覆盖: 匹配 master + 坏数据 → 失败。)
TEST(Download, AICHMasterMismatchDegrades){
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
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::optional<AICHHash>(bad_root))
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peer.port()}}).build();
    auto r = co_await dl.run(15s, 3);
    EXPECT_TRUE(r.has_value());   // master 不匹配 → 降级 → 无 AICH 下载 → 成功
    if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  std::filesystem::remove_all(dir);
}

// === P4c-3 raccoon 多源并发 e2e (S4) ===
// serve_subset_peer: 报告 have_parts 位图 (FILESTATUS 只标己有 part), 服务任意请求块
// (worker 经 next_block_for_parts 只请求对端有该 part 的块, 故仅会请求己有 part 的块)。
// 复用 serve_full_peer(full,...) 的握手/分派序列, 仅 FILESTATUS 位图按 have_parts 编码。
static asio::awaitable<void> serve_subset_peer(tcp::socket s, const std::vector<std::byte>& full,
                                               const FileHash& fhash, const std::vector<PartHash>& parts,
                                               const std::vector<bool>& have_parts,
                                               bool send_hello_first = false){
  using namespace ed2k::peer;
  HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
  if(send_hello_first){
    co_await send_pkt(s, op::HELLO, encode_hello_packet(h));
    (void)co_await read_frame(s);
  } else {
    (void)co_await read_frame(s);
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h));
  }
  (void)co_await read_frame(s);                          // SETREQFILEID
  { codec::ByteWriter w; w.hash16(fhash);
    w.u16(static_cast<std::uint16_t>(parts.size()));
    std::size_t nbytes = (parts.size() + 7) / 8;
    for(std::size_t i=0;i<nbytes;++i){
      std::uint8_t b=0;
      for(std::size_t bit=0; bit<8 && i*8+bit < have_parts.size(); ++bit)
        if(have_parts[i*8+bit]) b |= static_cast<std::uint8_t>(1u << bit);
      w.u8(b);
    }
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);                          // HASHSETREQUEST
  { codec::ByteWriter w; w.hash16(fhash); w.u16(static_cast<std::uint16_t>(parts.size()));
    for(const auto& p : parts) w.hash16(p);
    co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
  (void)co_await read_frame(s);                          // REQUESTFILENAME
  { codec::ByteWriter w; w.hash16(fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
    co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
  (void)co_await read_frame(s); co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});  // STARTUPLOADREQ
  for(;;){
    auto body = co_await read_frame(s);                  // REQUESTPARTS
    if(body.empty()){ co_await keep_alive(s); co_return; }
    codec::ByteReader r(std::span<const std::byte>(body).subspan(1));
    (void)r.hash16();
    std::uint32_t s0=r.u32(), s1=r.u32(), s2=r.u32(), e0=r.u32(), e1=r.u32(), e2=r.u32();
    (void)s1;(void)s2;(void)e1;(void)e2;
    if(s0==0 && e0==0){ co_await keep_alive(s); co_return; }
    std::size_t off = static_cast<std::size_t>(s0);
    std::size_t len = static_cast<std::size_t>(e0 - s0);
    codec::ByteWriter w; w.hash16(fhash); w.u32(s0); w.u32(e0);
    w.blob(std::span<const std::byte>(full).subspan(off, len));
    co_await send_pkt(s, op::SENDINGPART, w.take());
  }
  co_await keep_alive(s); co_return;
}

// raccoon 多源带宽聚合: 两个满文件源并发, 块来自 ≥2 源 (无块丢失/重复)。
// 单源也能完成, 故此测试主要验证 2 worker 并发共享 alloc 的正确性 (竞态安全网)。
TEST(Download, MultiSourceBothFull){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_ms_full"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  IoRuntime rt;
  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}); co_return; });
  ed2k::test::MockPeer peerB(rt.context());
  peerB.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peerA.port()}, SourceEndpoint{0x0100007Fu, peerB.port()}})
                .build();
    auto r = co_await dl.run(15s, 3);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  std::filesystem::remove_all(dir);
}

// raccoon 多源 per-part 聚合: A 持 part0, B 持 part1 (互补 per-part 子集)。双源并发完成
// 整文件 → 证 per-part 块模型下多源聚合语义正确。单源 (A 或 B) 各缺一半 part →
// next_block_for_parts 源耗尽退出 + active_workers<=1 → io_error, 必然失败; 双源成功即证聚合。
TEST(Download, MultiSourceAggregates){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_ms_agg"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  IoRuntime rt;
  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_subset_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}, {true, false}); co_return; });   // A: part0
  ed2k::test::MockPeer peerB(rt.context());
  peerB.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_subset_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}, {false, true}); co_return; });   // B: part1
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peerA.port()}, SourceEndpoint{0x0100007Fu, peerB.port()}})
                .build();
    auto r = co_await dl.run(15s, 3);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  std::filesystem::remove_all(dir);
}

// 反证: 单源 (A, 仅 part0) 无法完成 → io_error。补强 MultiSourceAggregates 的聚合断言
// (单源必然失败, 双源才成功)。
TEST(Download, MultiSourceSingleSubsetFails){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_ms_subset_fail"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  IoRuntime rt;
  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_subset_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}, {true, false}); co_return; });   // A: part0 only
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peerA.port()}}).build();
    auto r = co_await dl.run(15s, 3);
    EXPECT_FALSE(r.has_value());   // 单源仅 part0 → part1 永远缺 → 源耗尽 → io_error
    co_return;
  });
  std::filesystem::remove_all(dir);
}

// === P4c-3 M3 验收 (异步磁盘 I/O) ===
// 功能: Builder.disk_executor 注入真实 disk 线程池 → write_block_async 走卸载路径 (状态/I/O 分离)。
// 断言多源并发 + 异步磁盘路径下文件完整 + part-MD4 通过 (无竞态/腐败)。
TEST(Download, MultiSourceAsyncDiskOffload){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_ms_async_disk"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  IoRuntime rt;
  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}); co_return; });
  ed2k::test::MockPeer peerB(rt.context());
  peerB.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peerA.port()}, SourceEndpoint{0x0100007Fu, peerB.port()}})
                .disk_executor(rt.disk_executor())
                .build();
    auto r = co_await dl.run(15s, 3);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  std::filesystem::remove_all(dir);
}
// 结构: disk_executor 运行于独立线程 (≠ io_context::run 网络线程) → 磁盘 I/O/MD4 不阻塞网络线程。
// spec §5.6 心跳断言的更稳健替代 (非时序, 不 flaky): 证 disk 卸载架构成立。
TEST(Download, DiskExecutorRunsOnSeparateThread){
  IoRuntime rt;
  std::thread::id net_id, disk_id;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    net_id = std::this_thread::get_id();                              // io_context::run (网络) 线程
    co_await asio::post(rt.disk_executor(), asio::bind_executor(rt.disk_executor(), asio::use_awaitable));
    disk_id = std::this_thread::get_id();                             // disk_pool 线程
    co_return;
  });
  EXPECT_NE(net_id, disk_id) << "disk_executor 必须运行于独立线程 (M3 卸载前提)";
}

TEST(Download, DiskPoolIsSingleThreadByContract){
  static_assert(IoRuntime::disk_pool_thread_count == 1);
  EXPECT_EQ(IoRuntime::disk_pool_thread_count, 1u)
    << "PartFile f_ 由单 disk 线程串行访问; 改 >1 必须先加 strand";
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
      co_await serve_full_peer(std::move(c), full, mf.fhash, {mf.h0, mf.h1}, /*send_hello_first=*/true);
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
    auto dl = MultiSourceDownload::Builder(rt.executor())
                .out(tmp).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::move(srcs))
                .server(sc)
                .listener(lst)
                .build();
    auto r = co_await dl.run(20000ms, 3);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    co_return;
  });
  ASSERT_TRUE(std::filesystem::exists(tmp));
  EXPECT_EQ(std::filesystem::file_size(tmp), PART*2);
  std::filesystem::remove(tmp);
}

// P4c-3 M4: >4GiB 边界集成测试。file_size = 4GiB + 2*PART → part 442 整个位于 4GiB 之外
// (442*PART = 4301952000 > 4294967296)。验证 u64 偏移在 BlockAllocator→encode_request_parts_i64
// →PartFile.seekp/write/readback/MD4 全路径不发生 u32 窄化 (D3 根因, P4c-3 spec §3.1)。
// 仅下载 part 442 (满 part 53 块, ~9.7MB); PartFile 稀疏创建 (空文件 rehash_all 快速失败),
// 不实际写 4.3GiB 数据。替代原 RequestPartsI64RoundTrip skip (i64 round-trip 在此真实执行)。
TEST(Download, Beyond4GiBBoundaryRoundTrip){
  constexpr std::uint64_t GIB = std::uint64_t(4)*1024*1024*1024;          // 4 GiB = 4294967296
  std::uint64_t size = GIB + 2*PART;                                       // ~4.31 GiB → 444 parts
  std::size_t boundary_part = static_cast<std::size_t>(GIB / PART) + 1;    // 442, 起点 > 4GiB
  ASSERT_GT(static_cast<std::uint64_t>(boundary_part) * PART, GIB);        // 该 part 起点已超 4GiB
  std::size_t nparts = static_cast<std::size_t>((size + PART - 1) / PART); // 444

  // part 442 真实内容 (满 PART 字节) → MD4 即其 part hash; 其余 part hash 占位 (本测试不下载)。
  std::vector<std::byte> content(PART, std::byte{0x5A});
  crypto::MD4 m; m.update(content); PartHash boundary_hash = PartHash::from_bytes(m.finish());
  std::vector<PartHash> part_hashes(nparts, boundary_hash);
  // file_hash = MD4(所有 part hash 串联) — eD2k 规范; 仅 PartFile 构造需要, 不参与本测试校验。
  m = {}; for(auto& h : part_hashes) m.update(h.bytes());
  FileHash fhash = FileHash::from_bytes(m.finish());

  auto tmp = std::filesystem::temp_directory_path() / "ed2k_beyond4gib";
  auto met_path = std::filesystem::path(tmp.string() + ".part.met");
  std::filesystem::remove(tmp);
  std::filesystem::remove(met_path);
  // 预写 .part.met: 全文件为 gap → try_load_met 成功跳过 rehash_all (否则 444 part × 9.7MB
  // 分配开销 ~18s); 各 part 仍标未完成 (整文件 gap 覆盖每个 part) → 不影响下载/校验路径。
  {
    ed2k::PartFileState st; st.hash = fhash; st.part_hashes = part_hashes;
    st.gaps = {{0, size}};
    auto met_bytes = ed2k::write_part_met(st);
    std::ofstream m(met_path, std::ios::binary | std::ios::trunc);
    m.write(reinterpret_cast<const char*>(met_bytes.data()), static_cast<std::streamsize>(met_bytes.size()));
  }

  std::size_t blocks = 0;
  std::uint64_t last_end = boundary_part * PART;
  bool boundary_in_gaps = true;   // 默认假设未完成, 循环内由 gaps() 判定
  {
    PartFile pf(tmp, size, fhash, part_hashes);
    ASSERT_TRUE(pf.open_for_write());
    BlockAllocator alloc(size, part_hashes, std::nullopt, pf);
    std::vector<bool> has_part(nparts, false);
    has_part[boundary_part] = true;

    while(auto b = alloc.next_block_for_parts(has_part)){
      auto [part, bip, start, end] = *b;
      EXPECT_EQ(part, boundary_part);
      EXPECT_GT(start, GIB) << "块起始偏移必须 > 4GiB (u32 会溢出为低 32 位)";
      EXPECT_LT(start, end);
      EXPECT_LE(end, (boundary_part + 1) * PART);   // 块绝不跨 part 边界
      EXPECT_GE(start, last_end);                   // 块序单调不减
      last_end = end;

      // 1) I64 编解码 round-trip (原 skip 的承诺): u64 偏移不窄化。
      //    wire 布局 = file_hash(16) + 3×u64 starts(LE) + 3×u64 ends(LE)。
      auto wire = encode_request_parts_i64(fhash, {start,0,0}, {end,0,0});
      ASSERT_GE(wire.size(), 16u + 48u);
      auto rd = [&](std::size_t off){
        std::uint64_t v = 0;
        for(int i=0;i<8;++i) v |= std::uint64_t(std::to_integer<std::uint8_t>(wire[off+i])) << (8*i);
        return v;
      };
      EXPECT_EQ(rd(16), start);        // 第一个 start 原样 (>4GiB 高位非零)
      EXPECT_EQ(rd(16 + 24), end);     // 第一个 end 原样

      // 2) 切片 + 同步写盘 (seekp >4GiB, 稀疏); 内容正确 → part 满时 MD4 通过。
      std::uint64_t off_in_part = start - boundary_part * PART;
      std::vector<std::byte> slice(content.begin() + off_in_part,
                                   content.begin() + off_in_part + (end - start));
      auto wr = pf.write_block(start, end, slice);
      EXPECT_TRUE(wr.has_value()) << (wr ? "" : wr.error().message());
      blocks++;
    }

    // part 442 (>4GiB) 完成 → 不在 gaps() (write_block part 满时 MD4 通过即置 part_done_)。
    auto g = pf.gaps();
    boundary_in_gaps = false;
    std::uint64_t bp_start = boundary_part * PART, bp_end = (boundary_part + 1) * PART;
    for(auto& [gs, ge] : g) if(gs < bp_end && ge > bp_start) boundary_in_gaps = true;
  }  // pf/alloc 析构 → f_ 关闭落盘 (Windows 下 remove 前必须关闭)

  std::size_t expected_blocks = (PART + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;  // 满 part = 53
  EXPECT_EQ(blocks, expected_blocks);
  EXPECT_FALSE(boundary_in_gaps) << "part 442 (>4GiB) 必须已完成且 MD4 通过";
  EXPECT_GT(std::filesystem::file_size(tmp), GIB) << "文件必须已扩展到 4GiB 之外 (稀疏)";

  std::filesystem::remove(tmp);
  std::filesystem::remove(met_path);
}
