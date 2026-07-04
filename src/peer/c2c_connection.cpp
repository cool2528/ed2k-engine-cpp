#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
namespace ed2k::peer {
namespace asio = boost::asio;
using clock_type = std::chrono::steady_clock;

namespace {
// 累积 OP_SENDINGPART/OP_COMPRESSEDPART 子帧到 per-range 缓冲, 直到每个活跃区间 [start,end)
// 连续覆盖完成。aMule CreateStandardPackets 把每个请求区间切成 ~10240 字节的子帧(非一帧一块),
// 故不能假定「一区间一帧」——必须按字节偏移拼接。返回每个完成区间一个 Block(整区间数据)。
// 终止: 全部活跃区间覆盖完成 / OP_OUTOFPARTREQS(对端无更多块, 提前结束) / 超时 / FILEREQANSNOFIL。
// 子帧按 [b.start,b.end) ⊆ [starts[i],ends[i]) 归属区间 i; 仅接受连续推进(next[i] 起始 = start)。
template <class DecodePart>
asio::awaitable<tl::expected<std::vector<Block>, std::error_code>>
accumulate_blocks(net::Connection& conn, const FileHash& h,
                  std::array<std::uint64_t, 3> starts, std::array<std::uint64_t, 3> ends,
                  std::uint8_t op_sending, std::uint8_t op_compressed,
                  DecodePart decode_part, std::chrono::milliseconds timeout) {
  std::array<std::vector<std::byte>, 3> buf;
  std::array<std::uint64_t, 3> next{};
  std::array<bool, 3> active{}, done{};
  std::size_t active_cnt = 0;
  for (std::size_t i = 0; i < 3; ++i) {
    if (starts[i] < ends[i]) {                       // 真实请求区间
      active[i] = true; ++active_cnt;
      next[i] = starts[i];
      buf[i].resize(static_cast<std::size_t>(ends[i] - starts[i]));
    } else {
      done[i] = true;                                // 空/占位区间(start==end): 立即视为完成
    }
  }
  auto all_done = [&]() -> bool {
    for (std::size_t i = 0; i < 3; ++i) if (!done[i]) return false;
    return true;
  };
  auto deadline = clock_type::now() + timeout;
  while (!all_done()) {
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if (rem.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto rp = co_await conn.recv(rem);
    if (!rp) co_return tl::unexpected(rp.error());
    auto& pkt = *rp;
    if (pkt.opcode == op::OUTOFPARTREQS) break;                 // 对端不再供块: 提前结束
    if (pkt.opcode == op::FILEREQANSNOFIL) co_return tl::unexpected(make_error_code(errc::file_not_found));
    if (pkt.opcode != op_sending && pkt.opcode != op_compressed) continue;  // 其他帧(QUEUERANKING 等)忽略
    auto b = decode_part(pkt.opcode, pkt.payload);
    if (!b) co_return tl::unexpected(b.error());
    if (b->hash != h) continue;                                 // 非本文件帧: 丢弃
    if (b->end < b->start) continue;                            // 非法区间: 丢弃(防御)
    for (std::size_t i = 0; i < 3; ++i) {
      if (!active[i] || done[i]) continue;
      if (b->start < starts[i] || b->end > ends[i]) continue;   // 不属此区间: 试下一个
      std::uint64_t cs = std::max<std::uint64_t>(b->start, next[i]);  // 本帧中尚未覆盖的起点
      if (cs > next[i]) break;                                  // 间隙(非连续): 弃帧(aMule 顺序发送不应发生)
      if (b->end <= cs) break;                                  // 已完全覆盖(重叠帧): 忽略
      std::size_t off = static_cast<std::size_t>(cs - starts[i]);        // buf[i] 内偏移
      std::size_t sub_off = static_cast<std::size_t>(cs - b->start);     // 子帧内偏移
      std::size_t n = static_cast<std::size_t>(b->end - cs);
      if (off + n > buf[i].size() || sub_off + n > b->data.size()) break;  // 越界/不足: 弃帧(防御)
      std::copy_n(b->data.begin() + sub_off, n, buf[i].begin() + off);
      next[i] = b->end;
      if (next[i] >= ends[i]) done[i] = true;
      break;                                                    // 已归属区间 i: 不再试其他
    }
  }
  std::vector<Block> blocks;
  for (std::size_t i = 0; i < 3; ++i) {
    if (active[i] && done[i]) {
      Block bk; bk.hash = h; bk.start = starts[i]; bk.end = ends[i]; bk.data = std::move(buf[i]);
      blocks.push_back(std::move(bk));
    }
  }
  if (blocks.empty() && active_cnt > 0)
    co_return tl::unexpected(make_error_code(errc::io_error));   // 活跃区间无一覆盖完成
  co_return blocks;
}
}  // namespace

C2CConnection::C2CConnection(asio::any_io_executor ex) : conn_(ex) {}
void C2CConnection::close() noexcept { conn_.close(); }

asio::awaitable<tl::expected<void,std::error_code>>
C2CConnection::connect(IPv4 ip, std::uint16_t port, std::chrono::milliseconds timeout){
  co_return co_await conn_.connect(ip, port, timeout);
}

asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
C2CConnection::pump_until(std::uint8_t want, std::chrono::milliseconds budget){
  auto deadline = clock_type::now() + budget;
  while(true){
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if(rem.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto rp = co_await conn_.recv(rem);
    if(!rp) co_return tl::unexpected(rp.error());
    auto pkt = std::move(*rp);
    if(pkt.opcode == want) co_return std::move(pkt);
    if(pkt.opcode == ed2k::peer::op::QUEUERANKING) co_return tl::unexpected(make_error_code(errc::upload_queued));
    if(pkt.opcode == ed2k::peer::op::FILEREQANSNOFIL) co_return tl::unexpected(make_error_code(errc::file_not_found));
    continue;
  }
}

asio::awaitable<tl::expected<HelloInfo,std::error_code>>
C2CConnection::handshake(const HelloInfo& mine, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::HELLO; req.payload=encode_hello_packet(mine);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::HELLOANSWER, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_hello_answer(rp->payload);
}
asio::awaitable<tl::expected<HelloInfo,std::error_code>>
C2CConnection::handshake_acceptor(const HelloInfo& mine, std::chrono::milliseconds timeout){
  // acceptor: peer (TCP initiator) sends HELLO first; we decode it then reply HELLOANSWER.
  // HELLO 与 HELLOANSWER 不对称: HELLO 前导 0x10 hashsize 字节, HELLOANSWER 无前导(aMule BaseClient.cpp)。
  // 故对端 HELLO 用 decode_hello(校验并跳过 0x10);我方 HELLOANSWER 用 encode_hello(无前导)。
  auto rp = co_await pump_until(op::HELLO, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  auto peer = decode_hello(rp->payload);
  if(!peer) co_return tl::unexpected(peer.error());
  ed2k::net::Packet ans; ans.protocol=ed2k::net::proto::eDonkey; ans.opcode=op::HELLOANSWER; ans.payload=encode_hello(mine);
  auto sr = co_await conn_.send(ans);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return std::move(*peer);
}
asio::awaitable<tl::expected<FileStatus,std::error_code>>
C2CConnection::request_file(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::SETREQFILEID; req.payload=encode_set_req_file(h);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::FILESTATUS, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_file_status(rp->payload);
}
asio::awaitable<tl::expected<std::vector<PartHash>,std::error_code>>
C2CConnection::request_hashset(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::HASHSETREQUEST; req.payload=encode_hashset_request(h);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::HASHSETANSWER, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_hashset_answer(h, rp->payload);
}
asio::awaitable<tl::expected<std::string,std::error_code>>
C2CConnection::request_filename(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::REQUESTFILENAME; req.payload=encode_request_filename(h);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::REQFILENAMEANSWER, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  auto a = decode_req_filename_answer(rp->payload);
  if(!a) co_return tl::unexpected(a.error());
  co_return std::move(a->name);
}
asio::awaitable<tl::expected<void,std::error_code>>
C2CConnection::start_upload(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::STARTUPLOADREQ; req.payload=encode_start_upload(h);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::ACCEPTUPLOADREQ, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return tl::expected<void,std::error_code>{};
}
asio::awaitable<tl::expected<std::vector<Block>,std::error_code>>
C2CConnection::request_blocks(const FileHash& h, std::array<std::uint32_t,3> starts, std::array<std::uint32_t,3> ends, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::REQUESTPARTS; req.payload=encode_request_parts(h, starts, ends);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return co_await accumulate_blocks(conn_, h,
    std::array<std::uint64_t,3>{starts[0], starts[1], starts[2]},
    std::array<std::uint64_t,3>{ends[0], ends[1], ends[2]},
    op::SENDINGPART, op::COMPRESSEDPART,
    [](std::uint8_t oc, std::span<const std::byte> p) -> tl::expected<Block,std::error_code> {
      return oc == op::SENDINGPART ? decode_sending_part(p) : decode_compressed_part(p);
    }, timeout);
}

asio::awaitable<tl::expected<std::vector<Block>,std::error_code>>
C2CConnection::request_blocks_i64(const FileHash& h, std::array<std::uint64_t,3> starts, std::array<std::uint64_t,3> ends, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::REQUESTPARTS_I64; req.payload=encode_request_parts_i64(h, starts, ends);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return co_await accumulate_blocks(conn_, h, starts, ends,
    op::SENDINGPART_I64, op::COMPRESSEDPART_I64,
    [](std::uint8_t oc, std::span<const std::byte> p) -> tl::expected<Block,std::error_code> {
      return oc == op::SENDINGPART_I64 ? decode_sending_part_i64(p) : decode_compressed_part_i64(p);
    }, timeout);
}

asio::awaitable<tl::expected<AICHHash,std::error_code>>
C2CConnection::request_aich_master_hash(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eMule; req.opcode=op::AICHFILEHASHREQ;
  req.payload=encode_aich_file_hash_req(h);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::AICHFILEHASHANS, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_aich_file_hash_ans(rp->payload);
}

asio::awaitable<tl::expected<SourceExchangeAnswer,std::error_code>>
C2CConnection::request_sources2(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eMule; req.opcode=op::REQUESTSOURCES2;
  req.payload=encode_request_sources2(h);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::ANSWERSOURCES2, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  auto ans = decode_answer_sources2(rp->payload);
  if(!ans) co_return tl::unexpected(ans.error());
  if(ans->hash != h) co_return tl::unexpected(make_error_code(errc::hash_mismatch));
  co_return std::move(*ans);
}

asio::awaitable<tl::expected<void,std::error_code>>
C2CConnection::send_file_desc(std::uint8_t rating, std::string_view comment){
  ed2k::net::Packet req;
  req.protocol = ed2k::net::proto::eMule;
  req.opcode = op::FILEDESC;
  req.payload = encode_file_desc(rating, comment);
  co_return co_await conn_.send(req);
}

asio::awaitable<tl::expected<AICHRecoveryData,std::error_code>>
C2CConnection::request_aich_proof(const FileHash& h, const AICHHash& master, std::uint16_t part_index, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eMule; req.opcode=op::AICHREQUEST;
  req.payload=encode_aich_request(h, master, part_index);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::AICHANSWER, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  // 校验回显的 master_hash 与请求一致 (aMule DownloadClient.cpp:1634 ahMasterHash == GetMasterHash):
  // 帧 = file_hash(16) + part_index(2) + master_hash(20) + V2 data,master_hash 在偏移 18..38。
  {
    codec::ByteReader r(rp->payload);
    r.hash16();                          // file_hash(16)
    r.u16();                             // part_index(2)
    auto echoed = AICHHash::from_bytes(r.hash20());
    if(!r.ok() || echoed != master) co_return tl::unexpected(make_error_code(errc::hash_mismatch));
  }
  co_return decode_aich_answer(rp->payload);
}
}
