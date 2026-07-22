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
#include <boost/asio/cancel_after.hpp>
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
static asio::awaitable<void> send_pkt(tcp::socket& s, std::uint8_t op, std::span<const std::byte> pl, std::uint8_t proto_val = proto::eDonkey){
  Packet p; p.protocol=proto_val; p.opcode=op; p.payload.assign(pl.begin(),pl.end());
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
// Task 2: 下载侧握手现无条件跟进 eMule 扩展信息交换 (handshake_with_mule_info /
// handshake_acceptor_with_mule_info), 故所有 serve_* mock peer 必须在 HELLO 之后正确消费并
// 应答 EMULEINFO, 否则 pump_until 会把后续真实协议帧 (FILESTATUS 等) 当噪声悄悄吞掉, 导致
// 整个会话错位。方向与 HELLO 一致: send_hello_first=true 的一方 (主动发 HELLO 的一方, 如
// LowID 回调源) 也主动发 EMULEINFO 并等应答; 反之被动方等对端 EMULEINFO 再应答。
static asio::awaitable<void> exchange_mule_mock(tcp::socket& s, bool send_hello_first,
                                                std::uint16_t udp_port_answer = 4672){
  using namespace ed2k::peer;
  MuleInfo mine; mine.udp_port = udp_port_answer;
  if(send_hello_first){
    co_await send_pkt(s, op::EMULEINFO, encode_mule_info(mine), proto::eMule);
    (void)co_await read_frame(s);                        // EMULEINFOANSWER (内容不校验)
  } else {
    (void)co_await read_frame(s);                        // EMULEINFO
    co_await send_pkt(s, op::EMULEINFOANSWER, encode_mule_info(mine), proto::eMule);
  }
  co_return;
}
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
static asio::awaitable<void> serve_full_peer(tcp::socket s, const MockFile& mf, std::uint16_t udp_port_answer = 4672){
  using namespace ed2k::peer;
  std::vector<std::byte> full;
  full.insert(full.end(), mf.d0.begin(), mf.d0.end());
  full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  (void)co_await read_frame(s);                          // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  co_await exchange_mule_mock(s, false, udp_port_answer);
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
    // 审计 C6: 单次 REQUESTPARTS 最多携带 3 个真实区间(流水线), 逐槽解出后各自回 SENDINGPART
    // (占位槽位 start==end==0 跳过), 而非只读槽0/忽略槽1-2(否则生产侧新的 3-block 批量请求会
    // 卡在等永远不会到来的槽1/槽2 数据, 直到超时)。
    std::array<std::uint32_t,3> rs{}, re{};
    for(auto& v : rs) v = r.u32();
    for(auto& v : re) v = r.u32();
    if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
    for(std::size_t i=0;i<3;++i){
      if(rs[i]==0 && re[i]==0) continue;
      // flat 切片: [rs[i],re[i]) 可能跨 part 边界, 直接从 full 取
      std::size_t off = static_cast<std::size_t>(rs[i]);
      std::size_t len = static_cast<std::size_t>(re[i]-rs[i]);
      codec::ByteWriter w; w.hash16(mf.fhash); w.u32(rs[i]); w.u32(re[i]);
      w.blob(std::span<const std::byte>(full).subspan(off, len));
      co_await send_pkt(s, op::SENDINGPART, w.take());
    }
  }
  co_await keep_alive(s); co_return;
}
// Task 2 graceful-degrade fixture: 纯 eDonkey 对端——回 HELLOANSWER 后收到 EMULEINFO 但不
// 应答 (不支持 eMule 扩展, 也不认识该 opcode), 其余握手后流程与 serve_full_peer 完全一致。
// 用于验证下载侧在 exchange_mule_info 超时/失败时仍能正常完成整个下载 (source_udp_port()
// 退化为 0, 不影响握手/下载成功)。
static asio::awaitable<void> serve_full_peer_no_mule_ext(tcp::socket s, const MockFile& mf){
  using namespace ed2k::peer;
  std::vector<std::byte> full;
  full.insert(full.end(), mf.d0.begin(), mf.d0.end());
  full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  (void)co_await read_frame(s);                          // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  (void)co_await read_frame(s);                          // EMULEINFO — 消费但不应答 (刻意不支持)
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
    // 审计 C6: 逐槽解出最多 3 个真实区间(见 serve_full_peer 同款注释), 各自回 SENDINGPART。
    std::array<std::uint32_t,3> rs{}, re{};
    for(auto& v : rs) v = r.u32();
    for(auto& v : re) v = r.u32();
    if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
    for(std::size_t i=0;i<3;++i){
      if(rs[i]==0 && re[i]==0) continue;
      std::size_t off = static_cast<std::size_t>(rs[i]);
      std::size_t len = static_cast<std::size_t>(re[i]-rs[i]);
      codec::ByteWriter w; w.hash16(mf.fhash); w.u32(rs[i]); w.u32(re[i]);
      w.blob(std::span<const std::byte>(full).subspan(off, len));
      co_await send_pkt(s, op::SENDINGPART, w.take());
    }
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
  co_await exchange_mule_mock(s, send_hello_first);
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
    // 审计 C6: 逐槽解出最多 3 个真实区间(见 serve_full_peer(MockFile) 同款注释), 各自回 SENDINGPART。
    std::array<std::uint32_t,3> rs{}, re{};
    for(auto& v : rs) v = r.u32();
    for(auto& v : re) v = r.u32();
    if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
    for(std::size_t i=0;i<3;++i){
      if(rs[i]==0 && re[i]==0) continue;
      std::size_t off = static_cast<std::size_t>(rs[i]);
      std::size_t len = static_cast<std::size_t>(re[i]-rs[i]);
      codec::ByteWriter w; w.hash16(fhash); w.u32(rs[i]); w.u32(re[i]);
      w.blob(std::span<const std::byte>(full).subspan(off, len));
      co_await send_pkt(s, op::SENDINGPART, w.take());
    }
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
  co_await exchange_mule_mock(s, false);
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
      co_await send_pkt(s, op::AICHFILEHASHANS, w.take(), proto::eMule);
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
      co_await send_pkt(s, op::AICHANSWER, w.take(), proto::eMule);
      continue;
    }
    if(opcode == op::REQUESTPARTS){
      codec::ByteReader r(pl); (void)r.hash16();
      // 审计 C6: 逐槽解出最多 3 个真实区间(见 serve_full_peer 同款注释), 各自按自己的 blkidx
      // 判断是否命中 corrupt_idx 并回 SENDINGPART(不能只用槽0 的判定套用到其它槽位的数据)。
      std::array<std::uint32_t,3> rs{}, re{};
      for(auto& v : rs) v = r.u32();
      for(auto& v : re) v = r.u32();
      if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
      for(std::size_t i=0;i<3;++i){
        if(rs[i]==0 && re[i]==0) continue;
        std::size_t off = rs[i];
        std::size_t len = re[i] - rs[i];
        std::vector<std::byte> d(full.begin()+off, full.begin()+off+len);
        if(corrupt_block_n){
          // corrupt_idx 为 part 内块号; part0 起始偏移 0 → s0/AICH_BLOCK_SIZE == part0 块号。
          // part1 块号 = (s0-PART)/AICH_BLOCK_SIZE, 不会等于 part0 的 corrupt_idx。
          std::size_t blkidx = rs[i] / AICH_BLOCK_SIZE;
          if(blkidx == corrupt_idx) std::fill(d.begin(), d.end(), std::byte(0xFF));
        }
        codec::ByteWriter w; w.hash16(mf.fhash); w.u32(rs[i]); w.u32(re[i]); w.blob(std::span<const std::byte>(d));
        co_await send_pkt(s, op::SENDINGPART, w.take());
      }
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
// Task 2 (a): 源在 mule-info 握手中通告 udp_port=X (EMULEINFOANSWER), 下载侧应捕获该值并
// 通过 Download::source_udp_port() 暴露, 供未来 UDP reask 排队保活寻址 (Task 4)。
TEST(Download, CapturesSourceUdpPortViaMuleInfoHandshake){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_udp_port"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  constexpr std::uint16_t kSourceUdpPort = 5678;   // 刻意不同于其它测试用的默认 4672, 证明确实捕获了该值
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_full_peer(std::move(s), mf, kSourceUdpPort); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x0100007Fu, peer.port()});
    auto r = co_await dl.run(5s);
    EXPECT_TRUE(r.has_value()); if(!r) co_return;
    EXPECT_EQ(dl.source_udp_port(), kSourceUdpPort);
    co_return;
  });
  std::filesystem::remove_all(dir);
}
// Task 2 (b): 对端不支持 eMule 扩展 (纯 eDonkey, 不回 EMULEINFOANSWER) 时, exchange_mule_info
// 超时/失败必须优雅降级——不使整个握手/下载失败, 只是 source_udp_port() 退化为 0。
// 使用较短超时(300ms)以避免真等满 exchange_mule_info 的完整超时窗口拖慢测试。
TEST(Download, GracefullyDegradesWhenPeerLacksEmuleExtension){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_no_mule_ext"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_full_peer_no_mule_ext(std::move(s), mf); co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x0100007Fu, peer.port()});
    auto r = co_await dl.run(300ms);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    if(!r) co_return;
    EXPECT_EQ(dl.source_udp_port(), 0u);
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

// audit C5: 恶意源伪造一份"自洽"的假 hashset —— HASHSETANSWER 前导 file_hash 字段如实回显请求的
// mf.fhash(能通过 decode_hashset_answer 现有的 wire 级 file_hash 校验), 但两个 part hash 是攻击者
// 就着自己伪造的数据(fake.d0/d1, 与真实内容 mf.d0/d1 完全不同)算出来的——彼此"自洽"(per-block
// MD4 校验会通过, 因为实际服务的数据确实等于这两个 hash), 唯独拼接后的 MD4 不等于 mf.fhash(攻击
// 者算不出第二原像)。修复前, 这份垃圾 hashset 会被直接采纳进 PartFile, 后续全部块校验都按这份
// 错误基准走, 下载"成功"落地的其实是攻击者的伪造内容——这正是 C5 描述的完整性绕过(可用于污染
// 诚实源的数据或为伪造内容洗白)。修复后应在 fetch_hashset_phase 里即被拒绝为 hash_mismatch,
// 不采纳该 hashset。
TEST(Download, FakeSelfConsistentHashsetRejected){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_hashset_fake"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  MockFile fake;
  fake.d0.assign(PART, std::byte(0xAA));
  fake.d1.assign(PART, std::byte(0xBB));
  crypto::MD4 m; m.update(fake.d0); fake.h0 = PartHash::from_bytes(m.finish());
  m = {}; m.update(fake.d1); fake.h1 = PartHash::from_bytes(m.finish());
  fake.fhash = mf.fhash;   // 伪装成同一个"真实"文件: 前导字段回显请求 hash, 骗过既有 wire 级校验
  ASSERT_NE(fake.h0, mf.h0); ASSERT_NE(fake.h1, mf.h1);   // 确认这确实是一份与真实 part hash 不同的伪造

  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_full_peer(std::move(s), fake); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), path, mf.fhash, PART*2, SourceEndpoint{0x0100007Fu, peer.port()});
    auto r = co_await dl.run(5s);
    EXPECT_FALSE(r.has_value()) << "fake self-consistent hashset must not be silently accepted";
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::hash_mismatch));
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

// 审计 C6: 捕获每次收到的 REQUESTPARTS 的全部 3 个 (start,end) 槽位(不像其它 mock 那样只读
// 槽0/丢弃槽1-2), 按批次对每个非零槽位各回一个 SENDINGPART —— 既能验证生产侧真正发出的槽位
// 内容, 也对新旧两版生产代码都能正确供块(旧: 1 真 2 占位; 新: 最多 3 真)。
struct CapturedBatchRequest { std::array<std::uint32_t,3> starts; std::array<std::uint32_t,3> ends; };
static asio::awaitable<void> serve_full_peer_capturing_batches(
    tcp::socket s, const MockFile& mf, std::vector<CapturedBatchRequest>& captured) {
  using namespace ed2k::peer;
  std::vector<std::byte> full;
  full.insert(full.end(), mf.d0.begin(), mf.d0.end());
  full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  (void)co_await read_frame(s);                          // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  co_await exchange_mule_mock(s, false);
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
    std::array<std::uint32_t,3> starts{}, ends{};
    for(auto& v : starts) v = r.u32();
    for(auto& v : ends) v = r.u32();
    if(starts[0]==0 && ends[0]==0){ co_await keep_alive(s); co_return; }
    captured.push_back({starts, ends});
    for(std::size_t i=0;i<3;++i){
      if(starts[i]==0 && ends[i]==0) continue;           // 占位槽位: 跳过
      std::size_t off = static_cast<std::size_t>(starts[i]);
      std::size_t len = static_cast<std::size_t>(ends[i]-starts[i]);
      codec::ByteWriter w; w.hash16(mf.fhash); w.u32(starts[i]); w.u32(ends[i]);
      w.blob(std::span<const std::byte>(full).subspan(off, len));
      co_await send_pkt(s, op::SENDINGPART, w.take());
    }
  }
}

// 审计 C6 (3-block 请求流水线, TDD RED/GREEN 核心测试): 单源、无 AICH、2-part(每 part 53 块,
// 远多于 3) —— 断言首次 REQUESTPARTS 携带 3 个真实块区间(而非 1 真 2 占位), 且这 3 块完成后
// 紧接着的下一次请求携带紧随其后的 3 块(块序单调、无重复/无跳过), 证明流水线保持 3 块在途。
// 对当前(修复前)1-block-per-request 代码, count_real(captured[0]) 恒为 1, 本测试确定性 RED。
TEST(Download, PullBlocksPhasePipelinesThreeBlocksPerRequestParts){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_pipeline3"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  std::filesystem::remove(path); std::filesystem::remove(path.string()+".part.met");
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<CapturedBatchRequest> captured;
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_full_peer_capturing_batches(std::move(s), mf, captured); co_return; });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peer.port()}}).build();
    auto r = co_await dl.run(15s, 3);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    co_return;
  });
  auto count_real = [](const CapturedBatchRequest& req){
    std::size_t n=0;
    for(std::size_t i=0;i<3;++i) if(!(req.starts[i]==0 && req.ends[i]==0)) ++n;
    return n;
  };
  ASSERT_GE(captured.size(), 2u) << "expected at least 2 REQUESTPARTS batches for a 106-block file";
  EXPECT_EQ(count_real(captured[0]), 3u)
      << "single REQUESTPARTS must carry 3 real block ranges when >=3 blocks are available "
         "(eMule-standard pipelining), not 1 real + 2 zero-padding";
  EXPECT_EQ(captured[0].starts[0], 0u);
  EXPECT_EQ(captured[0].ends[2], 3u*AICH_BLOCK_SIZE);
  EXPECT_EQ(count_real(captured[1]), 3u);
  EXPECT_EQ(captured[1].starts[0], 3u*AICH_BLOCK_SIZE)
      << "second batch must continue from where the first left off (blocks 3,4,5), not repeat/skip";
  std::filesystem::remove_all(dir);
}

// === Task 5: peer_worker 排队等待集成 (P0) ===
// 单 block/单 part 极简文件(1000 字节, 远小于 AICH_BLOCK_SIZE/PART_SIZE), 跳过 hashset(size<=
// PART_SIZE)。EMULEINFO 故意不应答 -> source_udp_port()==0, 使排队等待循环走"纯 TCP 被动"分支
// (架构决策#3 else 分支), 无需搭建共享 UdpSocket 场景。
static constexpr std::uint64_t kQueueTestFileSize = 1000;

TEST(Download, WaitsInUploadQueueThenAcceptsAndDownloads){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_queue_accept"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  std::filesystem::remove(path); std::filesystem::remove(path.string()+".part.met");
  std::vector<std::byte> data(kQueueTestFileSize, std::byte(0x7A));
  crypto::MD4 m; m.update(data);
  auto fhash = FileHash::from_bytes(m.finish());

  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  bool premature_request_seen = false;   // 排队期间(收到 QUEUERANKING 之后, ACCEPTUPLOADREQ 之前)
                                          // 是否提前收到了 REQUESTPARTS —— 若有, 说明客户端没有真的
                                          // 在队列里等待(旧行为: 忽略 UploadQueued 直冲 block-dispatch)。
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);                          // HELLO
    { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
      co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
    co_await exchange_mule_mock(s, false, 0);              // 应答 udp_port=0 -> 排队等待走纯 TCP 被动分支
    (void)co_await read_frame(s);                          // SETREQFILEID
    { codec::ByteWriter w; w.hash16(fhash); w.u16(0);       // count=0: 对完整共享单 part 文件的既有约定
      co_await send_pkt(s, op::FILESTATUS, w.take()); }
    (void)co_await read_frame(s);                          // REQUESTFILENAME
    { codec::ByteWriter w; w.hash16(fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
      co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
    (void)co_await read_frame(s);                          // STARTUPLOADREQ
    co_await send_pkt(s, op::QUEUERANKING, encode_queue_ranking(3));

    // 观察窗口: 短超时探测客户端在 ACCEPTUPLOADREQ 之前是否提前发来 REQUESTPARTS。無論是否命中都
    // 照常处理该帧(供块), 避免旧(有 bug)实现让本协程卡在等一个不会再来的 REQUESTPARTS 上——
    // RED 阶段要能干净失败, 而不是超时挂起。
    std::optional<std::vector<std::byte>> pending;
    {
      std::array<std::byte,5> hdr;
      auto [e1,n1] = co_await asio::async_read(s, asio::buffer(hdr),
          asio::cancel_after(100ms, asio::as_tuple(asio::use_awaitable)));
      (void)n1;
      if(!e1){
        auto h = parse_header(hdr);
        if(h){
          std::vector<std::byte> body(h->size);
          auto [e2,n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
          (void)n2;
          if(!e2){ premature_request_seen = true; pending = std::move(body); }
        }
      }
    }
    co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});

    auto serve_one = [&](const std::vector<std::byte>& body) -> asio::awaitable<void> {
      if(body.empty()) co_return;
      codec::ByteReader r(std::span<const std::byte>(body).subspan(1));
      (void)r.hash16();
      // 审计 C6: 逐槽解出最多 3 个真实区间(本测试文件仅 1 块, 恒只有槽0非零, 但保持与其它
      // mock 一致的通用处理, 不假设"只有槽0"这一现已过时的前提)。
      std::array<std::uint32_t,3> rs{}, re{};
      for(auto& v : rs) v = r.u32();
      for(auto& v : re) v = r.u32();
      if(rs[0]==0 && re[0]==0) co_return;
      for(std::size_t i=0;i<3;++i){
        if(rs[i]==0 && re[i]==0) continue;
        std::size_t off = rs[i], len = re[i] - rs[i];
        codec::ByteWriter w; w.hash16(fhash); w.u32(rs[i]); w.u32(re[i]);
        w.blob(std::span<const std::byte>(data).subspan(off, len));
        co_await send_pkt(s, op::SENDINGPART, w.take());
      }
    };
    if(pending) co_await serve_one(*pending);   // 若确实提前收到(旧 bug 路径), 仍照常回块避免卡死
    for(;;){
      auto body = co_await read_frame(s);
      if(body.empty()){ co_await keep_alive(s); co_return; }
      co_await serve_one(body);
    }
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(fhash).size(kQueueTestFileSize).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peer.port()}}).build();
    auto r = co_await dl.run(5s, 3);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    if(!r) co_return;
    download::PartFile pf(path, kQueueTestFileSize, fhash, {});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  EXPECT_FALSE(premature_request_seen)
      << "client must hold off REQUESTPARTS until actually accepted (ACCEPTUPLOADREQ), not proceed while still queued";
  std::filesystem::remove_all(dir);
}

TEST(Download, CancelWhileQueuedExitsPromptlyAsCancelledNotTimedOut){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_queue_cancel"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  std::filesystem::remove(path); std::filesystem::remove(path.string()+".part.met");
  std::vector<std::byte> data(kQueueTestFileSize, std::byte(0x7A));
  crypto::MD4 m; m.update(data);
  auto fhash = FileHash::from_bytes(m.finish());
  auto stop = std::make_shared<bool>(false);

  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);                          // HELLO
    { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
      co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
    co_await exchange_mule_mock(s, false, 0);              // 应答 udp_port=0 -> 排队等待走纯 TCP 被动分支
    (void)co_await read_frame(s);                          // SETREQFILEID
    { codec::ByteWriter w; w.hash16(fhash); w.u16(0);
      co_await send_pkt(s, op::FILESTATUS, w.take()); }
    (void)co_await read_frame(s);                          // REQUESTFILENAME
    { codec::ByteWriter w; w.hash16(fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
      co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
    (void)co_await read_frame(s);                          // STARTUPLOADREQ
    co_await send_pkt(s, op::QUEUERANKING, encode_queue_ranking(3));

    // 关键: 用与"queue-then-accept"测试同款的观察窗口先判定客户端是否提前发了 REQUESTPARTS
    // (旧/有 bug 实现的特征)。这一步是让本测试在两种实现下都"确定性"而非"侥幸"通过/失败的核心——
    // 若只是简单地紧跟着发第二条 QUEUERANKING 再置位 stop, 旧实现恰好也可能在
    // pull_blocks_phase(既有代码, 循环顶部检查 st.stopped())第一次检查时就侥幸看到 stop 已置位而
    // "凑巧"快速退出, 使这条测试对本任务要实现的排队等待循环失去区分力。
    // 正确处理: 若确实提前收到(旧 bug 路径), 故意不回块——让客户端困在 accumulate_blocks 的阻塞
    // recv 里, 直到该请求自身的 per-op timeout(3s)才会因超时被动退出, 从而让下面的 elapsed 断言
    // 可靠地抓到这条旧路径(不看运气)。若没提前收到(新实现的排队等待, 纯 TCP 被动不会发送任何
    // 东西), 则走"发 stop 后再发一条 QUEUERANKING"的 happens-before 论证(见下)促使排队等待循环
    // 尽快检测到 stop。
    std::optional<std::vector<std::byte>> pending;
    {
      std::array<std::byte,5> hdr;
      auto [e1,n1] = co_await asio::async_read(s, asio::buffer(hdr),
          asio::cancel_after(100ms, asio::as_tuple(asio::use_awaitable)));
      (void)n1;
      if(!e1){
        auto h = parse_header(hdr);
        if(h){
          std::vector<std::byte> body(h->size);
          auto [e2,n2] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
          (void)n2;
          if(!e2) pending = std::move(body);
        }
      }
    }
    *stop = true;
    if(pending){
      // 旧 bug 路径: 客户端已经卡在等这条 REQUESTPARTS 的回应——故意不回块, 让它只能靠自身
      // per-op timeout 退出, elapsed 断言据此戳穿。
      co_await keep_alive(s); co_return;
    }
    // 新实现路径: 客户端仍在排队等待循环里被动监听 TCP, 再发一条 QUEUERANKING 促使它下一轮循环时
    // 检查到 stop(单线程协作式调度下的 happens-before: 客户端只可能在处理完这条帧、循环回排队等待
    // 顶部检查 stop 时看到它, 而这必然发生在 *stop=true 已执行之后)。
    co_await send_pkt(s, op::QUEUERANKING, encode_queue_ranking(2));
    co_await keep_alive(s); co_return;                     // 从不接受
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(fhash).size(kQueueTestFileSize).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peer.port()}})
                .stop_flag(stop)
                .build();
    const auto started = std::chrono::steady_clock::now();
    auto r = co_await dl.run(3s, 3);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_FALSE(r.has_value());
    if(!r) EXPECT_EQ(r.error(), make_error_code(errc::cancelled));
    // 关键区分点: 正确实现应在排队等待循环边界很快发现 stop 并退出(毫秒级), 而不是像旧行为那样
    // 忽略 UploadQueued 直冲 block-dispatch, 靠该请求自身的 per-op timeout(3s)才"凑巧"报 cancelled
    // (MultiSourceDownload::run 末尾的 st.stopped() 兜底会掩盖真实原因, 见 run_task 同款收尾逻辑)。
    // 用耗时上界戳穿这种"凑巧过"。
    EXPECT_LT(elapsed, 1s);
    co_return;
  });
  std::filesystem::remove_all(dir);
}

// === Task 5 review fix #1 (Important, 架构决策#4 完整性): AICH proof 等待期间的 QUEUERANKING ===
// 之前只有 accumulate_blocks(块传输阶段)识别中途 QUEUERANKING 并映射为 errc::upload_queued 走回
// queue_wait_phase; pull_blocks_phase 的 AICH 分支只看 request_aich_proof 返回值真假, 从不检查
// rd.error(), 于是 QUEUERANKING(经 pump_until 早已映射为同一 errc::upload_queued)落进"校验失败"
// 分支, 被当成数据损坏计入 max_retries, 耗尽后误判为 block_corrupt 放弃源。
//
// 本测试模拟"已被接受、正在传输中途"的降级(区别于 WaitsInUploadQueueThenAcceptsAndDownloads 测的
// 初始排队): STARTUPLOADREQ 后立即 ACCEPTUPLOADREQ → AICHFILEHASHREQ 正常协商 → 首块
// REQUESTPARTS/SENDINGPART 正常 → 该块的 AICHREQUEST 首次故意回 QUEUERANKING(模拟源把上传槽中途
// 收回排队)。用与既有排队测试同款 100ms 观察窗口区分两种实现:
//   - 有 bug 实现: AICH 分支不识别 upload_queued, 不等 ACCEPTUPLOADREQ 就立即用同一连接重下同一
//     块——观察窗口命中, mock 判定为旧路径, 不再服务并断开连接, 使下载确定性失败(RED)。
//   - 修复后实现: 原样传播 upload_queued, peer_worker 回 queue_wait_phase 被动等 TCP(纯被动分支
//     不会主动发任何帧)——观察窗口静默, mock 送 ACCEPTUPLOADREQ 促其恢复, 之后 AICHREQUEST 正常
//     应答, 下载完整完成(GREEN)。
//
// 文件大小取 AICH_BLOCK_SIZE+kQueueTestFileSize(单 part 两块): 若用单块文件, 该块叶标识符按
// AICHChecker::verify_block 的 leaf_ident 规则恒为 1(根), 而 proof map 显式排除 identifier==1,
// 永远验证不过——无法驱动"修复后应完整下载成功"这一路径, 故取两块规避此边界情形。
TEST(Download, MidTransferQueueRankingDuringAichProofWaitReentersQueueWait){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_aich_queue_mid"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  std::filesystem::remove(path); std::filesystem::remove(path.string()+".part.met");
  constexpr std::uint64_t kMidQueueFileSize = AICH_BLOCK_SIZE + kQueueTestFileSize;   // 单 part 双块
  std::vector<std::byte> data(kMidQueueFileSize, std::byte(0x7A));
  crypto::MD4 m; m.update(data);
  auto fhash = FileHash::from_bytes(m.finish());
  AICHHash root = aich_hash_bytes(data);
  auto part0_recovery = recovery_for(data, 0);   // part 级 proof(两叶), 与 serve_aich_peer 同款按 part 缓存

  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  bool premature_retry_seen = false;   // 旧 bug 特征: 不等 ACCEPTUPLOADREQ 就立即重下同一块
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);                          // HELLO
    { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
      co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
    co_await exchange_mule_mock(s, false, 0);              // 应答 udp_port=0 -> 排队等待走纯 TCP 被动分支
    (void)co_await read_frame(s);                          // SETREQFILEID
    { codec::ByteWriter w; w.hash16(fhash); w.u16(0);       // count=0: 对完整共享单 part 文件的既有约定
      co_await send_pkt(s, op::FILESTATUS, w.take()); }
    (void)co_await read_frame(s);                          // REQUESTFILENAME
    { codec::ByteWriter w; w.hash16(fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
      co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
    (void)co_await read_frame(s);                          // STARTUPLOADREQ
    co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});          // 立即接受: 测的是接受后的中途降级

    bool degraded_once = false;
    for(;;){
      auto body = co_await read_frame(s);
      if(body.empty()){ co_await keep_alive(s); co_return; }
      std::uint8_t opcode = std::to_integer<std::uint8_t>(body[0]);
      std::span<const std::byte> pl(body.data()+1, body.size()-1);
      if(opcode == op::AICHFILEHASHREQ){
        codec::ByteWriter w; w.hash16(fhash); w.hash20(root.bytes());
        co_await send_pkt(s, op::AICHFILEHASHANS, w.take(), proto::eMule);
        continue;
      }
      if(opcode == op::AICHREQUEST){
        codec::ByteReader r(pl); (void)r.hash16();
        std::uint16_t part_index = r.u16();
        auto echoed_master = r.hash20();
        if(!degraded_once){
          degraded_once = true;
          // 模拟源中途把该连接的上传槽收回排队(而非数据损坏): 回 QUEUERANKING 代替 AICHANSWER。
          co_await send_pkt(s, op::QUEUERANKING, encode_queue_ranking(5));
          // 观察窗口: 探测客户端是否不等 ACCEPTUPLOADREQ 就抢先发新请求(旧 bug 特征)。
          std::array<std::byte,5> hdr;
          auto [e1,n1] = co_await asio::async_read(s, asio::buffer(hdr),
              asio::cancel_after(100ms, asio::as_tuple(asio::use_awaitable)));
          (void)n1;
          if(!e1){
            // 窗口内收到新帧 = 旧 bug 路径(未等 ACCEPTUPLOADREQ 就抢先重下该块)。不再服务,
            // 断开连接让本次下载确定性失败, 而不是侥幸靠本地重试蒙混过关。
            premature_retry_seen = true;
            co_return;
          }
          co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});   // 确认静默等待后促其从排队等待恢复
          continue;
        }
        const auto& proof = part0_recovery;
        codec::ByteWriter w; w.hash16(fhash); w.u16(part_index); w.hash20(echoed_master);
        w.u16(static_cast<std::uint16_t>(proof.size()));
        for(const auto& p : proof){ w.u16(static_cast<std::uint16_t>(p.identifier)); w.hash20(p.hash); }
        w.u16(0);   // count32(非大文件路径)
        co_await send_pkt(s, op::AICHANSWER, w.take(), proto::eMule);
        continue;
      }
      if(opcode == op::REQUESTPARTS){
        codec::ByteReader r(pl); (void)r.hash16();
        // 审计 C6: 逐槽解出最多 3 个真实区间(见 serve_full_peer 同款注释), 各自回 SENDINGPART。
        std::array<std::uint32_t,3> rs{}, re{};
        for(auto& v : rs) v = r.u32();
        for(auto& v : re) v = r.u32();
        if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
        for(std::size_t i=0;i<3;++i){
          if(rs[i]==0 && re[i]==0) continue;
          std::size_t off = rs[i], len = re[i] - rs[i];
          codec::ByteWriter w; w.hash16(fhash); w.u32(rs[i]); w.u32(re[i]);
          w.blob(std::span<const std::byte>(data).subspan(off, len));
          co_await send_pkt(s, op::SENDINGPART, w.take());
        }
        continue;
      }
      // 其它 opcode 忽略
    }
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(fhash).size(kMidQueueFileSize).aich(std::optional<AICHHash>(root))
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peer.port()}}).build();
    auto r = co_await dl.run(5s, 3);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    if(!r) co_return;
    download::PartFile pf(path, kMidQueueFileSize, fhash, {});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  EXPECT_FALSE(premature_retry_seen)
      << "peer_worker must re-enter queue_wait_phase on mid-transfer QUEUERANKING during AICH-proof "
         "wait, not treat it as a corrupt-block retry (Decision #4 must also cover the AICH-proof path)";
  std::filesystem::remove_all(dir);
}

TEST(Download, RequiredObfuscationWithoutPeerHashFailsBeforeTcpDial) {
  IoRuntime rt;
  tcp::acceptor acceptor(rt.executor(), tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  const auto out = std::filesystem::temp_directory_path() / "ed2k_required_missing_hash";
  std::filesystem::remove(out);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    Download download(rt.executor(), out, FileHash{}, 1,
                      PeerIdentity{{0x0100007Fu, acceptor.local_endpoint().port()}, std::nullopt},
                      ObfuscationPolicy::required,
                      *UserHash::from_hex("00112233445566778899aabbccddeeff"));
    auto result = co_await download.run(200ms);
    EXPECT_FALSE(result.has_value());
    auto [ec, socket] = co_await acceptor.async_accept(
        asio::cancel_after(50ms, asio::as_tuple(asio::use_awaitable)));
    EXPECT_EQ(ec, asio::error::operation_aborted);
    EXPECT_FALSE(socket.is_open());
    co_return;
  });
  std::filesystem::remove(out);
}

TEST(Download, ResumesFromAmulePartMetSibling){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_amule_resume"; std::filesystem::create_directories(dir);
  auto path = dir/"001.part";
  auto met = path; met += ".met";
  auto wrong_met = path; wrong_met += ".part.met";
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());

  {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(mf.d0.data()), static_cast<std::streamsize>(mf.d0.size()));
  }
  {
    PartFileState st;
    st.hash = mf.fhash;
    st.part_hashes = {mf.h0, mf.h1};
    st.size = PART * 2;
    st.gaps = {{PART, PART * 2}};
    auto bytes = write_part_met(st);
    std::ofstream m(met, std::ios::binary | std::ios::trunc);
    m.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }

  IoRuntime rt;
  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_full_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1});
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peer.port()}})
                .build();
    auto r = co_await dl.run(15s, 3);
    EXPECT_TRUE(r.has_value()) << (r? "" : r.error().message());
    if(!r) co_return;
    download::PartFile pf(path, PART*2, mf.fhash, {mf.h0, mf.h1});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  EXPECT_TRUE(std::filesystem::exists(met));
  EXPECT_FALSE(std::filesystem::exists(wrong_met)) << "aMule .part output must not create 001.part.part.met";
  EXPECT_EQ(std::filesystem::file_size(path), PART * 2);
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
  co_await exchange_mule_mock(s, send_hello_first);
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
    // 审计 C6: 逐槽解出最多 3 个真实区间(见 serve_full_peer 同款注释), 各自回 SENDINGPART
    // (worker 经 next_blocks_for_parts 只请求对端有该 part 的块, 故仅会请求己有 part 的块)。
    std::array<std::uint32_t,3> rs{}, re{};
    for(auto& v : rs) v = r.u32();
    for(auto& v : re) v = r.u32();
    if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
    for(std::size_t i=0;i<3;++i){
      if(rs[i]==0 && re[i]==0) continue;
      std::size_t off = static_cast<std::size_t>(rs[i]);
      std::size_t len = static_cast<std::size_t>(re[i]-rs[i]);
      codec::ByteWriter w; w.hash16(fhash); w.u32(rs[i]); w.u32(re[i]);
      w.blob(std::span<const std::byte>(full).subspan(off, len));
      co_await send_pkt(s, op::SENDINGPART, w.take());
    }
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

// audit C5 mock: 恶意源——FILESTATUS/HASHSETANSWER 前导 file_hash 字段如实回显请求的 fhash(能过
// decode_hashset_answer 现有的 wire 级校验), 但 HASHSETANSWER 里的两个 part hash 是攻击者随意
// 伪造的值。fetch_hashset() 只走到 HASHSETANSWER 就返回(不会再发 REQUESTFILENAME/STARTUPLOADREQ),
// 故这里发完 HASHSETANSWER 后 keep_alive 等客户端因 hash_mismatch 主动断开即可, 无需服务后续帧。
static asio::awaitable<void> serve_fake_hashset_peer(tcp::socket s, const FileHash& fhash,
                                                     const PartHash& fake_h0, const PartHash& fake_h1) {
  using namespace ed2k::peer;
  (void)co_await read_frame(s);                          // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  co_await exchange_mule_mock(s, false);
  (void)co_await read_frame(s);                          // SETREQFILEID
  { codec::ByteWriter w; w.hash16(fhash); w.u16(2); w.u8(0xFF); w.u8(0x03);  // 两 part 都有
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);                          // HASHSETREQUEST
  { codec::ByteWriter w; w.hash16(fhash); w.u16(2); w.hash16(fake_h0); w.hash16(fake_h1);
    co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
  co_await keep_alive(s); co_return;
}
// audit C5 (多源场景): 首个源(A)提供伪造的 hashset(fhash 如实回显, part hash 伪造), 第二个源(B)
// 提供真实 hashset + 完整数据。fetch_hashset() 的 setup 阶段应在 A 处因 hash_mismatch 被拒绝
// (is_transient 判定其为 terminal, 不重连 A)、顺次尝试 B——B 合法, 下载改用 B 的 hashset 完成,
// 证明"拒绝该源"不等于"拒绝整个下载"(还有其它源时应继续尝试), 且最终落盘内容必须是真实内容
// (用真实 h0/h1 重新构造 PartFile 独立校验 complete())。
TEST(Download, MultiSourceFakeHashsetSourceSkippedFallsBackToLegit){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_ms_hashset_fake"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  auto fake_h0 = *PartHash::from_hex("11111111111111111111111111111111");
  auto fake_h1 = *PartHash::from_hex("22222222222222222222222222222222");
  IoRuntime rt;
  ed2k::test::MockPeer peerA(rt.context());   // A: 伪造 hashset
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_fake_hashset_peer(std::move(s), mf.fhash, fake_h0, fake_h1); co_return; });
  ed2k::test::MockPeer peerB(rt.context());   // B: 真实 hashset + 完整数据
  peerB.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_full_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}); co_return; });
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

// === Task 6: 源重试/重连 + 编排周期重问 (P0) ===
// 单 block/单 part 极简文件(与 Task 5 的 kQueueTestFileSize 同款), 跳过 hashset。
static constexpr std::uint64_t kReconnectTestFileSize = 1000;

// mock peer: fetch_hashset 阶段(HELLO..FILESTATUS)如实应答成功, 随后不响应任何后续帧就直接
// 断开(协程返回, socket 析构关闭)——模拟 run_source_session(start_upload_phase)阶段的瞬时
// 连接丢失(对客户端而言是 connection_closed/timed_out, 均属 is_transient)。
static asio::awaitable<void> serve_drop_after_filestatus(tcp::socket s, const FileHash& fhash){
  (void)co_await read_frame(s);                          // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  co_await exchange_mule_mock(s, false, 0);
  (void)co_await read_frame(s);                          // SETREQFILEID
  { codec::ByteWriter w; w.hash16(fhash); w.u16(0);
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  co_return;                                              // 故意不再响应, 直接断开
}
// mock peer: 正常完整握手 + 供整个文件(与 Task 5 WaitsInUploadQueueThenAcceptsAndDownloads 同款
// 单 part 小文件手写服务端, 跳过 hashset)。
static asio::awaitable<void> serve_small_file_full(tcp::socket s, const FileHash& fhash,
                                                    const std::vector<std::byte>& data){
  (void)co_await read_frame(s);                          // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  co_await exchange_mule_mock(s, false, 0);
  (void)co_await read_frame(s);                          // SETREQFILEID
  { codec::ByteWriter w; w.hash16(fhash); w.u16(0);
    co_await send_pkt(s, op::FILESTATUS, w.take()); }
  (void)co_await read_frame(s);                          // REQUESTFILENAME
  { codec::ByteWriter w; w.hash16(fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
    co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
  (void)co_await read_frame(s);                          // STARTUPLOADREQ
  co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});
  for(;;){
    auto body = co_await read_frame(s);                  // REQUESTPARTS
    if(body.empty()){ co_await keep_alive(s); co_return; }
    codec::ByteReader r(std::span<const std::byte>(body).subspan(1));
    (void)r.hash16();
    // 审计 C6: 逐槽解出最多 3 个真实区间(见 serve_full_peer 同款注释), 各自回 SENDINGPART。
    std::array<std::uint32_t,3> rs{}, re{};
    for(auto& v : rs) v = r.u32();
    for(auto& v : re) v = r.u32();
    if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
    for(std::size_t i=0;i<3;++i){
      if(rs[i]==0 && re[i]==0) continue;
      std::size_t off = rs[i], len = re[i] - rs[i];
      codec::ByteWriter w; w.hash16(fhash); w.u32(rs[i]); w.u32(re[i]);
      w.blob(std::span<const std::byte>(data).subspan(off, len));
      co_await send_pkt(s, op::SENDINGPART, w.take());
    }
  }
}

// transient 断开一次后重连恢复: 唯一源的第一次连接在 fetch_hashset 阶段正常应答, 但之后
// (run_source_session 阶段)不告而断; 若 peer_worker 没有重连逻辑, 整个源在此彻底放弃,
// dl.run() 必然失败; 若有(本任务实现), 应对同一源发起全新 TCP 连接重试, 第二次连接完整
// 供文件, 下载最终成功。
//
// 关键实现细节: ed2k::test::MockPeer::serve() 每次调用各自独立 co_await acceptor_.async_accept(),
// 若提前注册两个 handler 再等连接到达, asio 不保证"先注册的 handler 拿到先到达的连接"(实测确实
// 会反过来, 见 RED 阶段记录于 task-6-report.md)——与 session_test.cpp PauseResumeCancelLifecycle
// 里 "MockPeer/MockServer 的 serve() 只 accept 一次" 那条注释描述的是同一类限制。本测试改用该
// 测试同款手写单一 acceptor + accept 循环: 循环体在拿到一个连接后才决定"这是第几次连接"再派发
// 对应行为, 从而按连接到达的真实顺序(而非注册顺序)确定性地区分"第一次(丢弃)"与"第二次
// (完整服务, 即重连)"。
TEST(Download, TransientDropThenReconnectCompletes){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_reconnect"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  std::filesystem::remove(path); std::filesystem::remove(path.string()+".part.met");
  std::vector<std::byte> data(kReconnectTestFileSize, std::byte(0x5B));
  crypto::MD4 m; m.update(data);
  auto fhash = FileHash::from_bytes(m.finish());

  IoRuntime rt;
  tcp::acceptor acceptor(rt.context(), tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  const std::uint16_t peer_port = acceptor.local_endpoint().port();
  int connection_count = 0;
  bool second_connection_served = false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
    for(;;){
      auto [ec, sock] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      { boost::system::error_code ndc; sock.set_option(tcp::no_delay(true), ndc); }
      ++connection_count;
      const bool is_first = (connection_count == 1);
      if(!is_first) second_connection_served = true;
      asio::co_spawn(rt.context(),
        [sock = std::move(sock), is_first, &fhash, &data]() mutable -> asio::awaitable<void>{
          try {
            if(is_first) co_await serve_drop_after_filestatus(std::move(sock), fhash);
            else co_await serve_small_file_full(std::move(sock), fhash, data);
          } catch(...) {}
          co_return;
        }, asio::detached);
    }
  }, asio::detached);

  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(fhash).size(kReconnectTestFileSize).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peer_port}}).build();
    // source_reask_interval 对本测试无意义(未注入 .server(), 监督不会启动); 用一个较短的
    // source_reconnect_backoff 让重连退避不拖慢测试。
    auto r = co_await dl.run(5s, 3, kSourceReaskInterval, 50ms);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    if(!r) co_return;
    download::PartFile pf(path, kReconnectTestFileSize, fhash, {});
    EXPECT_TRUE(pf.complete());
    co_return;
  });
  EXPECT_EQ(connection_count, 2)
      << "expected exactly one drop + one reconnect (not zero, not more)";
  EXPECT_TRUE(second_connection_served)
      << "peer_worker must reconnect to the same source after a transient drop, not give up permanently";
  std::filesystem::remove_all(dir);
}

// 周期重问返回新源→加入并联合完成下载。初始只给 A(仅 part0, 与 MultiSourceSingleSubsetFails
// 完全同一 fixture——那条测试证明"仅 A 必然 io_error"), 但本测试额外注入一个真实
// server::ServerConnection + MockServer: 监督的首次周期重问(source_reask_interval 覆盖为
// 很短)会调用 get_sources, mock 服务器返回 B(仅 part1)的端点。若监督正确合并新源并为其
// 启动新 worker, B 加入后与 A 互补完成整文件, dl.run() 成功——与 MultiSourceSingleSubsetFails
// 的失败结果形成直接对照, 证明"周期重问确实让此前会失败的下载改为成功"。
TEST(Download, PeriodicRequeryAddsNewSourceAndCompletes){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_requery_add"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  IoRuntime rt;

  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_subset_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}, {true, false}); co_return; });   // A: part0 only
  ed2k::test::MockPeer peerB(rt.context());
  bool peer_b_connected = false;
  peerB.serve([&](tcp::socket s) -> asio::awaitable<void>{
    peer_b_connected = true;
    co_await serve_subset_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}, {false, true}); co_return; });   // B: part1 only

  // mock 搜索服务器: 登录后对每一次 GETSOURCES 都回一个仅含 B 的 FOUNDSOURCES(循环应答, 因为
  // supervisor 存活期间会反复重问; 已知源 B 在第二次起会被 known_sources 去重, 不会重复 spawn)。
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    co_await send_pkt(s, server::op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    for(;;){
      auto body = co_await read_frame(s);   // GETSOURCES
      if(body.empty()) co_return;           // 连接已断(下载已结束)
      codec::ByteWriter w; w.hash16(mf.fhash); w.u8(1);
      w.u32(0x0100007Fu); w.u16(peerB.port());
      co_await send_pkt(s, server::op::FOUNDSOURCES, w.take());
    }
  });

  auto tmp = std::filesystem::temp_directory_path()/"ed2k_requery_add_out"; std::filesystem::remove(tmp);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    server::ServerConnection sc(rt.executor());
    server::LoginParams p; p.nickname="u"; p.client_port=0;
    p.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
    auto lr = co_await sc.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 3000ms);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;

    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(tmp).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peerA.port()}})   // 仅 A, 无 B
                .server(sc)
                .build();
    // source_reask_interval 覆盖为 50ms(生产默认 3 分钟), 使监督的首次周期重问尽快发生;
    // source_reconnect_backoff 本测试用不到, 用默认值。
    auto r = co_await dl.run(15s, 3, 50ms, kSourceReconnectBackoff);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });
  EXPECT_TRUE(peer_b_connected)
      << "source_reask_supervisor must dial the newly-merged source returned by a later get_sources";
  ASSERT_TRUE(std::filesystem::exists(tmp));
  EXPECT_EQ(std::filesystem::file_size(tmp), PART*2);
  std::filesystem::remove(tmp);
  std::filesystem::remove_all(dir);
}

// Task 6 review 修复 Critical#1 覆盖: source_reask_supervisor 动态加入的源, 若首次连接 transient
// 掉线需要重连, peer_worker 必须仍持有有效的 source。修复前 source 是引用参数, 指向 supervisor
// 循环体里早已析构的 loop-local identity, 第二次(重连)读取即悬垂 UB(可能连错端口/间歇失败);
// 修复(按值参数)后协程帧独立持有该源, 重连稳定。本测试正是那条"supervisor-spawned 源 + 需重连"
// 路径: 初始仅 A(part0), 服务器周期重问返回 B(part1); B 第一次连接在 hashset 阶段前不告而断
// (transient), peer_worker 对同一 B 发起重连, 第二次完整供 part1, 下载成功。
TEST(Download, SupervisorSpawnedSourceReconnectsAfterTransientDrop){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_super_reconnect"; std::filesystem::create_directories(dir);
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  IoRuntime rt;

  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_subset_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}, {true, false}); co_return; });   // A: part0 only

  // B: 手写 acceptor 区分第一次(掉线, transient)与第二次(完整供 part1)连接 —— 理由同
  // TransientDropThenReconnectCompletes 的注释(asio 不保证注册顺序=到达顺序)。
  tcp::acceptor acceptorB(rt.context(), tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  const std::uint16_t peerB_port = acceptorB.local_endpoint().port();
  int b_connection_count = 0;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
    for(;;){
      auto [ec, sock] = co_await acceptorB.async_accept(asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      { boost::system::error_code ndc; sock.set_option(tcp::no_delay(true), ndc); }
      ++b_connection_count;
      const bool is_first = (b_connection_count == 1);
      asio::co_spawn(rt.context(),
        [sock = std::move(sock), is_first, &mf, &full]() mutable -> asio::awaitable<void>{
          try {
            if(is_first) co_await serve_drop_after_filestatus(std::move(sock), mf.fhash);
            else co_await serve_subset_peer(std::move(sock), full, mf.fhash, {mf.h0, mf.h1}, {false, true});
          } catch(...) {}
          co_return;
        }, asio::detached);
    }
  }, asio::detached);

  // mock 搜索服务器: 每次 GETSOURCES 回仅含 B 的 FOUNDSOURCES(循环应答; B 会被 known_sources 去重,
  // 只 spawn 一次 B worker, 该 worker 内部自行重连)。
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    co_await send_pkt(s, server::op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    for(;;){
      auto body = co_await read_frame(s);   // GETSOURCES
      if(body.empty()) co_return;
      codec::ByteWriter w; w.hash16(mf.fhash); w.u8(1);
      w.u32(0x0100007Fu); w.u16(peerB_port);
      co_await send_pkt(s, server::op::FOUNDSOURCES, w.take());
    }
  });

  auto tmp = std::filesystem::temp_directory_path()/"ed2k_super_reconnect_out"; std::filesystem::remove(tmp);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    server::ServerConnection sc(rt.executor());
    server::LoginParams p; p.nickname="u"; p.client_port=0;
    p.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
    auto lr = co_await sc.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 3000ms);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;

    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(tmp).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peerA.port()}})   // 仅 A, B 靠周期重问加入
                .server(sc)
                .build();
    // reask 周期短(尽快加入 B); 重连退避短(尽快重连)。
    auto r = co_await dl.run(15s, 3, 50ms, 50ms);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });
  EXPECT_GE(b_connection_count, 2)
      << "supervisor-spawned source B must reconnect after its first (transient) drop, not read a dangling source";
  ASSERT_TRUE(std::filesystem::exists(tmp));
  EXPECT_EQ(std::filesystem::file_size(tmp), PART*2);
  std::filesystem::remove(tmp);
  std::filesystem::remove_all(dir);
}

// Task 6 review 修复 Important#1 覆盖: 源真正耗尽(文件无法补齐)且服务器也提供不了新源时,
// source_reask_supervisor 必须有界放弃, 让 run() 及时以源耗尽错误返回, 而不是永久挂在
// downloading/0B/s。初始仅 A(part0, 与 MultiSourceSingleSubsetFails 同 fixture, part1 永缺),
// 注入的 mock 服务器每次 GETSOURCES 都回空源集 —— 连续 kMaxEmptyReaskCycles 轮空转后监督放弃,
// dl.run() 返回失败(而非一直挂到总超时才结束)。
TEST(Download, SupervisorGivesUpWhenSourcesExhausted){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_super_giveup"; std::filesystem::create_directories(dir);
  auto path = dir/"out";
  auto mf = make_mock_file(0x11, 0x22);
  std::vector<std::byte> full; full.insert(full.end(), mf.d0.begin(), mf.d0.end()); full.insert(full.end(), mf.d1.begin(), mf.d1.end());
  IoRuntime rt;

  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_subset_peer(std::move(s), full, mf.fhash, {mf.h0, mf.h1}, {true, false}); co_return; });   // A: part0 only

  // mock 服务器: 每次 GETSOURCES 都回空(u8=0 无源)——服务器帮不上忙, 迫使监督走"无源可用"放弃路径。
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);   // LOGINREQUEST
    co_await send_pkt(s, server::op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    for(;;){
      auto body = co_await read_frame(s);   // GETSOURCES
      if(body.empty()) co_return;
      codec::ByteWriter w; w.hash16(mf.fhash); w.u8(0);   // 0 个源
      co_await send_pkt(s, server::op::FOUNDSOURCES, w.take());
    }
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    server::ServerConnection sc(rt.executor());
    server::LoginParams p; p.nickname="u"; p.client_port=0;
    p.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
    auto lr = co_await sc.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 3000ms);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;

    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(mf.fhash).size(PART*2).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peerA.port()}})
                .server(sc)
                .build();
    // reask 周期短: 让 kMaxEmptyReaskCycles 轮空转迅速累积, 无需等真实分钟级。总超时给足 —— 断言的是
    // "有界返回失败"而非"超时挂起": 若监督未实现有界放弃, 本 run 会一直挂到 15s 都不返回。
    auto r = co_await dl.run(15s, 3, 30ms, kSourceReconnectBackoff);
    EXPECT_FALSE(r.has_value())
        << "sources exhausted + server offers nothing → supervisor must give up bounded, run returns error not hang";
    co_return;
  });
  std::filesystem::remove_all(dir);
}

// P1 Task 3(审计 C2)回归: 构造 alloc.complete()==true 而 pf.complete()==false 的真实分歧,
// 证明 run() 改用 pf.complete() 判定成功后, 不会在这种情况下误报"下载成功"。
//
// 构造原理: 单 part、恰 3 块的文件(每块整好 AICH_BLOCK_SIZE, 无 AICH 协商 → 直通
// write_block_async, 只靠 part 级 MD4 兜底)。源 A/B 对块2 全程只供坏数据(从未有人供出正确
// 内容), 对其余块供正确数据。首次凑满整 part 触发 MD4 校验 → 必然失败 → C1 重置该 part 全部
// 记账(block_done/part_filled/part_done 归零), 对应那次写入返回 block_corrupt(非
// is_transient, 该源终止放弃)。BlockAllocator::done_ 是 run() 私有的独立记账, 不受 C1 重置
// 影响——先前已成功写入的块在 alloc 里仍标 done, 只有触发失败的那一块被 requeue。
//
// 周期重问(50ms)注入第二个源, 对(仅剩的)那一块再次写入: write_block_async 这次只把这一块的
// 字节数累加进 part_filled(reset 后从 0 起, 远小于整 part 大小), 永远追不上"part 已填满"的
// 判定阈值——该 part 的 MD4 校验从此再也不会被触发, 这次写入无条件"成功"返回。于是
// alloc.mark_block_done 被调用, alloc 认为整个(单 part)文件 complete()==true; 但
// PartFile::part_done[0] 仍是 false(该 part 从未真正通过 MD4), 磁盘上块2 的字节其实一直是
// 坏数据, 从未被验证。旧实现(run() 末尾用 st.alloc.complete() 判成功)会在此刻误报成功。
TEST(Download, MultiSourceAllocCompleteButPartFileIncompleteIsNotSuccess){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_dl_alloc_pf_divergence";
  std::filesystem::create_directories(dir);
  auto path = dir/"out";
  std::filesystem::remove(path); std::filesystem::remove(path.string()+".part.met");

  constexpr std::uint64_t kBlk = AICH_BLOCK_SIZE;
  constexpr std::uint64_t kFileSize = 3 * kBlk;            // 单 part, 恰 3 整块, 无部分块边界
  constexpr std::uint64_t kCorruptOff = 2 * kBlk;          // 块2: 全程无人供出其正确数据
  std::vector<std::byte> data(kFileSize, std::byte(0x11));     // "真相"内容(仅块0/块1 及算 hash 用)
  crypto::MD4 m; m.update(data);
  auto fhash = FileHash::from_bytes(m.finish());
  std::vector<std::byte> corrupt_block(kBlk, std::byte(0xEE));  // A/B 对块2 蓄意供的坏数据

  // 单 part 简单上传流程(跳过排队, 立即 accept); 对块2 的 REQUESTPARTS 恒回坏数据,
  // 其余块回正确数据。A/B 共用同一份逻辑(参数通过闭包捕获)。
  auto serve_with_bad_block2 = [&](tcp::socket s) -> asio::awaitable<void> {
    (void)co_await read_frame(s);                            // HELLO
    { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
      co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
    co_await exchange_mule_mock(s, false, 0);
    (void)co_await read_frame(s);                            // SETREQFILEID
    { codec::ByteWriter w; w.hash16(fhash); w.u16(0);         // count=0: 完整共享单 part 文件
      co_await send_pkt(s, op::FILESTATUS, w.take()); }
    (void)co_await read_frame(s);                            // REQUESTFILENAME
    { codec::ByteWriter w; w.hash16(fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
      co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
    (void)co_await read_frame(s);                            // STARTUPLOADREQ
    co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});
    for(;;){
      auto body = co_await read_frame(s);                    // REQUESTPARTS
      if(body.empty()){ co_await keep_alive(s); co_return; }
      codec::ByteReader r(std::span<const std::byte>(body).subspan(1));
      (void)r.hash16();
      // 审计 C6: 逐槽解出最多 3 个真实区间(见 serve_full_peer 同款注释), 各自按自己的偏移判断
      // 是否命中 kCorruptOff(不能只用槽0 的判定套用到其它槽位)。
      std::array<std::uint32_t,3> rs{}, re{};
      for(auto& v : rs) v = r.u32();
      for(auto& v : re) v = r.u32();
      if(rs[0]==0 && re[0]==0){ co_await keep_alive(s); co_return; }
      for(std::size_t i=0;i<3;++i){
        if(rs[i]==0 && re[i]==0) continue;
        std::size_t off = rs[i], len = re[i] - rs[i];
        codec::ByteWriter w; w.hash16(fhash); w.u32(rs[i]); w.u32(re[i]);
        if(static_cast<std::uint64_t>(off) == kCorruptOff) w.blob(std::span<const std::byte>(corrupt_block).subspan(0, len));
        else w.blob(std::span<const std::byte>(data).subspan(off, len));
        co_await send_pkt(s, op::SENDINGPART, w.take());
      }
    }
  };

  IoRuntime rt;
  ed2k::test::MockPeer peerA(rt.context());
  peerA.serve([&](tcp::socket s) -> asio::awaitable<void>{ co_await serve_with_bad_block2(std::move(s)); co_return; });
  ed2k::test::MockPeer peerB(rt.context());
  bool peer_b_connected = false;
  peerB.serve([&](tcp::socket s) -> asio::awaitable<void>{
    peer_b_connected = true;
    co_await serve_with_bad_block2(std::move(s)); co_return; });

  // mock 搜索服务器: 每次 GETSOURCES 都回一个仅含 B 的 FOUNDSOURCES, 驱动周期重问在 A 终止后
  // 补入 B(与 PeriodicRequeryAddsNewSourceAndCompletes 同款机制)。
  ed2k::test::MockServer srv(rt.context());
  srv.serve([&](tcp::socket s) -> asio::awaitable<void>{
    (void)co_await read_frame(s);                            // LOGINREQUEST
    co_await send_pkt(s, server::op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    for(;;){
      auto body = co_await read_frame(s);                    // GETSOURCES
      if(body.empty()) co_return;
      codec::ByteWriter w; w.hash16(fhash); w.u8(1);
      w.u32(0x0100007Fu); w.u16(peerB.port());
      co_await send_pkt(s, server::op::FOUNDSOURCES, w.take());
    }
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    server::ServerConnection sc(rt.executor());
    server::LoginParams p; p.nickname="u"; p.client_port=0;
    p.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
    auto lr = co_await sc.connect_and_login(*IPv4::from_dotted("127.0.0.1"), srv.port(), p, 3000ms);
    EXPECT_TRUE(lr.has_value()); if(!lr) co_return;

    auto dl = download::MultiSourceDownload::Builder(rt.executor())
                .out(path).hash(fhash).size(kFileSize).aich(std::nullopt)
                .sources(std::vector{SourceEndpoint{0x0100007Fu, peerA.port()}})   // 仅 A, B 靠周期重问加入
                .server(sc)
                .build();
    auto r = co_await dl.run(15s, 3, 50ms, kSourceReconnectBackoff);
    EXPECT_FALSE(r.has_value())
        << "block 2 was never verified by any source -- run() must not report success just because "
           "BlockAllocator's private bookkeeping considers every block written";
    if(r.has_value()) co_return;
    EXPECT_EQ(r.error(), make_error_code(errc::block_corrupt));
    co_return;
  });

  EXPECT_TRUE(peer_b_connected) << "test setup requires B to actually rejoin via periodic requery";

  // 直接证据: 磁盘上块2 仍是坏数据(全程无人供出正确内容), 从头重建的 PartFile 也判定未完成——
  // 与 run() 的失败结果一致; 而 alloc 的私有记账会认为"全部块已写"——这正是本测试要暴露的分歧。
  {
    std::ifstream f(path, std::ios::binary);
    ASSERT_TRUE(f.is_open());
    std::vector<std::byte> buf(kBlk);
    f.seekg(static_cast<std::streamoff>(kCorruptOff));
    f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(kBlk));
    ASSERT_EQ(static_cast<std::size_t>(f.gcount()), static_cast<std::size_t>(kBlk));
    EXPECT_TRUE(std::equal(buf.begin(), buf.end(), corrupt_block.begin()))
        << "block 2 on disk should still be the corrupt bytes -- no source ever supplied the real data";
  }
  {
    download::PartFile pf(path, kFileSize, fhash, {});
    EXPECT_FALSE(pf.complete())
        << "a freshly reconstructed PartFile must also see this file as incomplete/unverified";
  }   // 显式收窄作用域: pf 析构关闭文件句柄, 否则下面 remove_all 在 Windows 上会因文件占用而抛异常

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

// audit C1 (async 路径): write_block_async 是 MultiSourceDownload 生产主路径实际调用的写入,
// 其 MD4 失败分支必须与 sync write_block 一样重置该 part 记账, 否则生产路径下载的损坏 part 永不可
// 重验。镜像 PartFile.MD4MismatchResetsPartStateForRedownload 的场景, 但走 disk_executor 卸载路径。
TEST(Download, AsyncWriteBlockMD4MismatchResetsPartState){
  auto dir = std::filesystem::temp_directory_path()/"ed2k_pf_async_md4_reset"; std::filesystem::create_directories(dir);
  auto path = dir/"f";
  std::vector<std::byte> correct(PART, std::byte(0x11));
  std::vector<std::byte> corrupt(PART, std::byte(0xFF));   // 内容不同 -> 组装后 MD4 与期望不符
  crypto::MD4 m; m.update(correct);
  auto h0 = PartHash::from_bytes(m.finish());              // part 真实期望 hash (仅 correct 能通过)
  IoRuntime rt;
  {
  PartFile pf(path, PART, *FileHash::from_hex("00112233445566778899aabbccddeeff"), {h0});
  const std::size_t nb = static_cast<std::size_t>((PART + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    // 1) async 写入损坏数据全部块: 末块攒满触发 disk 线程 readback+MD4, 应失败并重置。
    for(std::size_t b=0; b<nb; ++b){
      std::uint64_t s = b*AICH_BLOCK_SIZE, e = std::min(s+AICH_BLOCK_SIZE, PART);
      auto w = co_await pf.write_block_async(s, e,
                     std::span(corrupt).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)),
                     rt.disk_executor());
      if(b+1 == nb) EXPECT_FALSE(w.has_value()) << "async 末块应触发 MD4 校验并因内容损坏失败";
    }
    EXPECT_FALSE(pf.complete());
    // 2) 状态应被重置: 该 part 全部块重新变为未完成。
    for(std::size_t b=0; b<nb; ++b)
      EXPECT_FALSE(pf.is_block_done(0, b)) << "async: block " << b << " 应在 MD4 失败后被重置";
    EXPECT_EQ(pf.pending_blocks().size(), nb) << "async: MD4 失败后该 part 全部块应重新待下载";
    // 3) async 重下正确数据: 若 part_filled 未归零(bug), 累计永不再等于整 part, MD4 不再触发,
    //    complete() 永久 false —— 本用例捕获的正是生产路径(write_block_async)的该回归。
    for(std::size_t b=0; b<nb; ++b){
      std::uint64_t s = b*AICH_BLOCK_SIZE, e = std::min(s+AICH_BLOCK_SIZE, PART);
      auto w = co_await pf.write_block_async(s, e,
                     std::span(correct).subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(e-s)),
                     rt.disk_executor());
      EXPECT_TRUE(w.has_value()) << "async: block " << b << " 重下正确数据应成功";
    }
    EXPECT_TRUE(pf.complete()) << "async 重下正确数据后该 part 应重新通过 MD4 并整体完成";
    co_return;
  });
  }
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

// P1 Task 5 (审计 C4): 单源 Download::dispatch_blocks_phase 请求 mock peer —— FILESTATUS 仅
// 声明一个指定 part(boundary_part)可用, 其余全部声明不可用; dispatch_blocks_phase 的
// missing_parts_peer_has 因此只会为这一个 part 发起块请求, 无需为其余 part 准备/传输数据
// (技巧与 Beyond4GiBBoundaryRoundTrip 一致, 但那里绕开了 C2CConnection, 直接摆弄
// BlockAllocator/PartFile; 这里要验证 dispatch_blocks_phase 实际发出的线上请求, 必须经真实
// C2CConnection 往返)。
// 捕获每次收到的 REQUESTPARTS(0x47, 32-bit)/REQUESTPARTS_I64(0xA3, 64-bit)请求的
// (opcode, 解码后按 u64 保留的 start/end)供测试断言。offset 若落在 boundary part 真实内容
// 范围之外(32-bit 回绕会回绕到 <4GiB 的错误位置, 落在其它 part), 只回一段等长占位数据,
// 不越界索引 content —— 该分支纯粹是防御性的, 断言直接读 captured, 不依赖响应数据本身。
struct CapturedPartsRequest { std::uint8_t opcode; std::uint64_t start; std::uint64_t end; };
static asio::awaitable<void> serve_boundary_part_peer(
    tcp::socket s, const FileHash& fhash, const std::vector<PartHash>& part_hashes,
    std::size_t boundary_part, const std::vector<std::byte>& content,
    std::vector<CapturedPartsRequest>& captured) {
  using namespace ed2k::peer;
  (void)co_await read_frame(s);                          // HELLO
  { HelloInfo h; h.nickname="peer"; h.user_hash=*UserHash::from_hex("00112233445566778899aabbccddeeff");
    co_await send_pkt(s, op::HELLOANSWER, encode_hello(h)); }
  co_await exchange_mule_mock(s, false);
  (void)co_await read_frame(s);                          // SETREQFILEID
  {
    // FILESTATUS: 仅 boundary_part 一位为 1, 其余为 0 (decode_file_status: bit i = byte[i/8]
    // 的 bit (i%8), LSB-first, 见 c2c_messages.cpp decode_file_status)。其余 443 part 因而
    // 永远不会进入 dispatch_blocks_phase 的 missing 集合, 不需要真实数据。
    codec::ByteWriter w; w.hash16(fhash);
    w.u16(static_cast<std::uint16_t>(part_hashes.size()));
    std::size_t nbytes = (part_hashes.size() + 7) / 8;
    std::vector<std::uint8_t> bits(nbytes, 0);
    bits[boundary_part/8] |= static_cast<std::uint8_t>(1u << (boundary_part%8));
    for(auto b : bits) w.u8(b);
    co_await send_pkt(s, op::FILESTATUS, w.take());
  }
  (void)co_await read_frame(s);                          // HASHSETREQUEST
  { codec::ByteWriter w; w.hash16(fhash); w.u16(static_cast<std::uint16_t>(part_hashes.size()));
    for(const auto& p : part_hashes) w.hash16(p);
    co_await send_pkt(s, op::HASHSETANSWER, w.take()); }
  (void)co_await read_frame(s);                          // REQUESTFILENAME
  { codec::ByteWriter w; w.hash16(fhash); w.u32(4); w.blob(bytes({'n','a','m','e'}));
    co_await send_pkt(s, op::REQFILENAMEANSWER, w.take()); }
  (void)co_await read_frame(s); co_await send_pkt(s, op::ACCEPTUPLOADREQ, {});  // STARTUPLOADREQ

  const std::uint64_t bstart = static_cast<std::uint64_t>(boundary_part) * PART;
  for(;;){
    auto body = co_await read_frame(s);                  // REQUESTPARTS 或 REQUESTPARTS_I64
    if(body.empty()) co_return;
    std::uint8_t opcode = std::to_integer<std::uint8_t>(body[0]);
    std::span<const std::byte> pl(body.data()+1, body.size()-1);
    std::array<std::uint64_t,3> starts{}, ends{};
    if(opcode == op::REQUESTPARTS){
      codec::ByteReader r(pl); (void)r.hash16();
      std::array<std::uint32_t,3> rs{}, re{};
      for(auto& v : rs) v = r.u32();
      for(auto& v : re) v = r.u32();
      for(std::size_t i=0;i<3;++i){ starts[i] = rs[i]; ends[i] = re[i]; }
    } else if(opcode == op::REQUESTPARTS_I64){
      codec::ByteReader r(pl); (void)r.hash16();
      for(auto& v : starts) v = r.u64();
      for(auto& v : ends) v = r.u64();
    } else {
      continue;                                          // 其它 opcode 忽略
    }
    // 审计 C6: 单次 REQUESTPARTS(_I64) 最多携带 3 个真实区间(流水线批量请求)——逐个非占位槽位
    // 各捕获一条 CapturedPartsRequest 并各回一个 SENDINGPART(_I64), 使既有断言
    // captured.size()==expected_blocks(53, 一 part 满块数) 不受批量打包影响: 无论生产侧一次
    // REQUESTPARTS 里塞了 1 个还是 3 个真实区间, 这里统计的始终是"总共请求到的块数"。
    for(std::size_t i=0;i<3;++i){
      if(starts[i]==0 && ends[i]==0) continue;
      std::uint64_t s0 = starts[i], e0 = ends[i];
      captured.push_back({opcode, s0, e0});
      std::size_t len = static_cast<std::size_t>(e0 - s0);
      std::vector<std::byte> d;
      if(s0 >= bstart && e0 <= bstart + content.size()){
        std::size_t off = static_cast<std::size_t>(s0 - bstart);
        d.assign(content.begin()+off, content.begin()+off+len);
      } else {
        d.assign(len, std::byte{0});                        // 落在 content 范围外: 安全占位, 不越界
      }
      if(opcode == op::REQUESTPARTS_I64){
        codec::ByteWriter w; w.hash16(fhash); w.u64(s0); w.u64(e0); w.blob(std::span<const std::byte>(d));
        co_await send_pkt(s, op::SENDINGPART_I64, w.take(), proto::eMule);
      } else {
        codec::ByteWriter w; w.hash16(fhash);
        w.u32(static_cast<std::uint32_t>(s0)); w.u32(static_cast<std::uint32_t>(e0));
        w.blob(std::span<const std::byte>(d));
        co_await send_pkt(s, op::SENDINGPART, w.take());
      }
    }
  }
}

// P1 Task 5 (审计 C4): 单源 Download::dispatch_blocks_phase 对 >4GiB 文件必须使用 64-bit
// REQUESTPARTS_I64 分支(修复前恒用 32-bit REQUESTPARTS —— offset 转 u32 时静默回绕, 落在
// 错误 part 触发静默数据损坏; 修复后与 MultiSourceDownload::pull_blocks_phase 的 large_file
// 分支一致, 按 size>4GiB 选择 64-bit 请求)。
// 构造 4GiB+2*PART 文件(与 Beyond4GiBBoundaryRoundTrip 同一构造), FILESTATUS 仅声明
// boundary_part(起点 4,299,776,000 > 4GiB)可用 —— 其余 443 part 因而被
// missing_parts_peer_has 跳过, 无需真实传输 4.3GiB 数据; 预写 .part.met(gaps=全文件)跳过
// PartFile 构造时的 rehash_all 全量扫描(同一技巧, 见 Beyond4GiBBoundaryRoundTrip 注释)。
// 断言两层:
//   1) 线路层——mock peer 捕获到的每次请求必须是 REQUESTPARTS_I64, 且解码后的 u64 offset
//      必须 >= 4GiB(32-bit 回绕会产生 <4GiB 的错误值, 直接证伪回绕)。
//   2) 落盘层(round-trip)——boundary part 必须真正 MD4 校验通过、从 gaps() 消失: 回绕 bug 会
//      把请求/写入错误地路由到 part 0/1 的中段(既不触发那两个 part 的 MD4, 也永远碰不到
//      boundary_part), 该 part 会永远停留在 gaps() 里。
TEST(Download, SingleSourceBeyond4GiBUsesI64Requests){
  constexpr std::uint64_t GIB = std::uint64_t(4)*1024*1024*1024;          // 4 GiB = 4294967296
  std::uint64_t size = GIB + 2*PART;                                       // ~4.31 GiB → 444 parts
  std::size_t boundary_part = static_cast<std::size_t>(GIB / PART) + 1;    // 442, 起点 > 4GiB
  ASSERT_GT(static_cast<std::uint64_t>(boundary_part) * PART, GIB);
  std::size_t nparts = static_cast<std::size_t>((size + PART - 1) / PART); // 444
  const std::uint64_t bstart = static_cast<std::uint64_t>(boundary_part) * PART;

  std::vector<std::byte> content(PART, std::byte{0x5A});
  crypto::MD4 m; m.update(content); PartHash boundary_hash = PartHash::from_bytes(m.finish());
  std::vector<PartHash> part_hashes(nparts, boundary_hash);   // 其余 part hash 占位(本测试不下载)
  m = {}; for(auto& h : part_hashes) m.update(h.bytes());
  FileHash fhash = FileHash::from_bytes(m.finish());

  auto tmp = std::filesystem::temp_directory_path() / "ed2k_dl_i64_single";
  auto met_path = std::filesystem::path(tmp.string() + ".part.met");
  std::filesystem::remove(tmp);
  std::filesystem::remove(met_path);
  {
    ed2k::PartFileState st; st.hash = fhash; st.part_hashes = part_hashes;
    st.gaps = {{0, size}};
    auto met_bytes = ed2k::write_part_met(st);
    std::ofstream mm(met_path, std::ios::binary | std::ios::trunc);
    mm.write(reinterpret_cast<const char*>(met_bytes.data()), static_cast<std::streamsize>(met_bytes.size()));
  }

  std::vector<CapturedPartsRequest> captured;
  IoRuntime rt; ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    co_await serve_boundary_part_peer(std::move(s), fhash, part_hashes, boundary_part, content, captured);
    co_return;
  });
  run_coro(rt, [&]() -> asio::awaitable<void>{
    download::Download dl(rt.executor(), tmp, fhash, size, SourceEndpoint{0x0100007Fu, peer.port()});
    // 全文件仅 1/444 part 对 peer 可用, pf.complete() 恒为 false —— 不能作为本测试的判据
    // (与 dispatch_blocks_phase 的 32-bit/64-bit 分支是否正确无关), 结果本身仅忽略。
    (void)co_await dl.run(5s);
    co_return;
  });

  std::size_t expected_blocks = (PART + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;  // 满 part = 53
  ASSERT_FALSE(captured.empty()) << "mock peer 从未收到任何 REQUESTPARTS(_I64) 请求";
  EXPECT_EQ(captured.size(), expected_blocks);
  for(const auto& req : captured){
    EXPECT_EQ(req.opcode, ed2k::peer::op::REQUESTPARTS_I64)
        << "size>4GiB 时必须使用 64-bit REQUESTPARTS_I64, 而非 32-bit REQUESTPARTS(offset 会静默回绕)";
    EXPECT_GE(req.start, GIB) << "解码后的请求偏移已回绕到 4GiB 以下(32-bit narrowing 的典型症状)";
    EXPECT_GE(req.end, GIB);
  }

  {
    PartFile pf(tmp, size, fhash, part_hashes);
    auto g = pf.gaps();
    bool boundary_in_gaps = false;
    for(auto& [gs, ge] : g) if(gs < bstart + PART && ge > bstart) boundary_in_gaps = true;
    EXPECT_FALSE(boundary_in_gaps) << "boundary part (>4GiB) 必须下载完成且 MD4 校验通过 (round-trip)";
  }

  std::filesystem::remove(tmp);
  std::filesystem::remove(met_path);
}
