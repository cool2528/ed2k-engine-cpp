#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/net/connection.hpp"
#include "ed2k/net/encrypted_stream_socket.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"
#include "ed2k/hash/aich_hasher.hpp"   // PART_SIZE(C3 修复: compressed_size 上限校验用)
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <variant>
namespace ed2k::peer {
namespace asio = boost::asio;
using clock_type = std::chrono::steady_clock;

namespace {
std::optional<std::chrono::milliseconds> remaining(clock_type::time_point deadline) {
  auto value = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
  if (value.count() <= 0) return std::nullopt;
  return value;
}

std::chrono::milliseconds preferred_negotiation_budget(std::chrono::milliseconds available) {
  if (available <= std::chrono::milliseconds{1}) return available;
  const auto minimum_reserve = std::min(std::chrono::milliseconds{50}, available / 2);
  auto reserve = std::max(minimum_reserve, available / 4);
  reserve = std::min(reserve, std::chrono::milliseconds{2000});
  return available - reserve;
}
// 累积 OP_SENDINGPART/OP_COMPRESSEDPART 子帧到 per-range 缓冲, 直到每个活跃区间 [start,end)
// 连续覆盖完成。aMule CreateStandardPackets 把每个请求区间切成 ~10240 字节的子帧(非一帧一块),
// 故不能假定「一区间一帧」——必须按字节偏移拼接。返回每个完成区间一个 Block(整区间数据)。
// 终止: 全部活跃区间覆盖完成 / OP_OUTOFPARTREQS(对端无更多块, 提前结束) / 超时 / FILEREQANSNOFIL。
// 子帧按 [b.start,b.end) ⊆ [starts[i],ends[i]) 归属区间 i; 仅接受连续推进(next[i] 起始 = start)。
template <class Stream, class DecodeSendingPart, class DecodeCompressedSegment>
asio::awaitable<tl::expected<std::vector<Block>, std::error_code>>
accumulate_blocks(Stream& conn, const FileHash& h,
                  std::array<std::uint64_t, 3> starts, std::array<std::uint64_t, 3> ends,
                  std::uint8_t op_sending, std::uint8_t op_compressed,
                  DecodeSendingPart decode_sending_part,
                  DecodeCompressedSegment decode_compressed_segment,
                  std::chrono::milliseconds timeout) {
  std::array<std::vector<std::byte>, 3> buf;
  std::array<std::uint64_t, 3> next{};
  std::array<bool, 3> active{}, done{};
  struct PendingCompressed {
    FileHash hash;
    std::uint64_t start = 0;
    std::uint32_t compressed_size = 0;
    std::vector<std::byte> data;
  };
  std::vector<PendingCompressed> pending_compressed;
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
  auto consume_block = [&](Block&& b) {
    if (b.hash != h) return;                                      // 非本文件帧: 丢弃
    if (b.end < b.start) return;                                  // 非法区间: 丢弃(防御)
    for (std::size_t i = 0; i < 3; ++i) {
      if (!active[i] || done[i]) continue;
      if (b.start < starts[i] || b.end > ends[i]) continue;       // 不属此区间: 试下一个
      std::uint64_t cs = std::max<std::uint64_t>(b.start, next[i]);  // 本帧中尚未覆盖的起点
      if (cs > next[i]) break;                                    // 间隙(非连续): 弃帧(aMule 顺序发送不应发生)
      if (b.end <= cs) break;                                     // 已完全覆盖(重叠帧): 忽略
      std::size_t off = static_cast<std::size_t>(cs - starts[i]);        // buf[i] 内偏移
      std::size_t sub_off = static_cast<std::size_t>(cs - b.start);      // 子帧内偏移
      std::size_t n = static_cast<std::size_t>(b.end - cs);
      if (off + n > buf[i].size() || sub_off + n > b.data.size()) break; // 越界/不足: 弃帧(防御)
      std::copy_n(b.data.begin() + sub_off, n, buf[i].begin() + off);
      next[i] = b.end;
      if (next[i] >= ends[i]) done[i] = true;
      break;                                                      // 已归属区间 i: 不再试其他
    }
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
    // P0 架构决策#4: 中途(已被接受、正在传输块的过程中)收到 QUEUERANKING = 源把上传槽回收,
    // 把我方重新打回排队(eD2k 协议允许的正常事件, 不是错误)。旧行为在此静默 continue 忽略,
    // 调用方(pull_blocks_phase)会继续傻等一个不会再来的块直到自己的 per-op timeout——表现为
    // 一次"沉默死亡"。改为显式识别并向上抛出一个调用方能映射回"回到排队等待"的信号——复用
    // errc::upload_queued(与 pump_until 对其余调用方的既有 QUEUERANKING 语义同一个错误码,
    // 同属"遇到了 QUEUERANKING"这一概念, 只是这里发生在块传输过程中)。让 peer_worker 据此
    // 回到 queue_wait_phase 而不是把该源判死。
    if (pkt.opcode == op::QUEUERANKING) co_return tl::unexpected(make_error_code(errc::upload_queued));
    if (pkt.opcode != op_sending && pkt.opcode != op_compressed) continue;  // 其他帧忽略
    if (pkt.opcode == op_sending) {
      auto b = decode_sending_part(pkt.payload);
      if (!b) co_return tl::unexpected(b.error());
      consume_block(std::move(*b));
      continue;
    }

    auto seg = decode_compressed_segment(pkt.payload);
    if (!seg) co_return tl::unexpected(seg.error());
    if (seg->hash != h) continue;
    if (seg->data.size() > seg->compressed_size)
      co_return tl::unexpected(make_error_code(errc::decompress_failed));
    // C3 安全修复: compressed_size 是未认证的线上 u32, 攻击者可用一个 ~24 字节的分段
    // 声明 compressed_size ≈ 4GiB, 诱导下面 pending.data.reserve() 尝试一次巨量分配
    // (远程、未认证、单包 DoS)。真实压缩数据不会超过一个 part 的原始大小(压缩不会让
    // 数据显著膨胀; 发送端 upload_session 也只在 packed_size < 原始大小时才启用压缩),
    // 故用协议原生的 PART_SIZE(单 part 上限, 比实际单块请求的 AICH_BLOCK_SIZE 更宽松但
    // 仍足够保守)作为上限, 必须在 reserve 之前拒绝越界声明, 不能先分配后校验。
    if (seg->compressed_size > PART_SIZE)
      co_return tl::unexpected(make_error_code(errc::packet_too_large));
    auto it = std::find_if(pending_compressed.begin(), pending_compressed.end(),
      [&](const PendingCompressed& p) {
        return p.hash == seg->hash && p.start == seg->start && p.compressed_size == seg->compressed_size;
      });
    if (it == pending_compressed.end()) {
      PendingCompressed pending;
      pending.hash = seg->hash;
      pending.start = seg->start;
      pending.compressed_size = seg->compressed_size;
      pending.data.reserve(seg->compressed_size);
      pending_compressed.push_back(std::move(pending));
      it = std::prev(pending_compressed.end());
    }
    if (it->data.size() + seg->data.size() > it->compressed_size)
      co_return tl::unexpected(make_error_code(errc::decompress_failed));
    it->data.insert(it->data.end(), seg->data.begin(), seg->data.end());
    if (it->data.size() == it->compressed_size) {
      CompressedPartSegment full;
      full.hash = it->hash;
      full.start = it->start;
      full.compressed_size = it->compressed_size;
      full.data = std::move(it->data);
      pending_compressed.erase(it);
      auto b = inflate_compressed_part_segment(full);
      if (!b) co_return tl::unexpected(b.error());
      consume_block(std::move(*b));
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

struct C2CConnection::Impl {
  using Stream = std::variant<net::Connection, net::EncryptedStreamSocket>;
  explicit Impl(asio::any_io_executor executor)
    : ex(executor), stream(std::in_place_type<net::Connection>, executor) {}
  explicit Impl(asio::ip::tcp::socket&& socket)
    : ex(socket.get_executor()), remote(peer_ip(socket)),
      stream(std::in_place_type<net::Connection>, std::move(socket)) {}
  Impl(net::EncryptedStreamSocket&& socket, std::optional<IPv4> remote_ip)
    : ex(socket.executor()), remote(std::move(remote_ip)),
      stream(std::in_place_type<net::EncryptedStreamSocket>, std::move(socket)) {}

  static std::optional<IPv4> peer_ip(const asio::ip::tcp::socket& socket) {
    boost::system::error_code ec;
    auto endpoint = socket.remote_endpoint(ec);
    if (ec || !endpoint.address().is_v4()) return std::nullopt;
    return IPv4::from_host(endpoint.address().to_v4().to_uint());
  }

  asio::awaitable<tl::expected<void,std::error_code>> send(const net::Packet& packet) {
    co_return co_await std::visit([&](auto& socket) { return socket.send(packet); }, stream);
  }
  asio::awaitable<tl::expected<net::Packet,std::error_code>> recv(std::chrono::milliseconds timeout) {
    co_return co_await std::visit([&](auto& socket) { return socket.recv(timeout); }, stream);
  }
  void close() noexcept { std::visit([](auto& socket) { socket.close(); }, stream); }
  bool encrypted() const noexcept {
    auto* socket = std::get_if<net::EncryptedStreamSocket>(&stream);
    return socket && socket->encrypted();
  }
  void reset_plain() { stream.emplace<net::Connection>(ex); }
  void reset_encrypted() { stream.emplace<net::EncryptedStreamSocket>(ex); }

  asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
    pump_until(std::uint8_t want, std::chrono::milliseconds budget,
               std::optional<std::uint8_t> protocol = std::nullopt);
  // start_upload 专用等待: 与 pump_until 不同, QUEUERANKING 在此不是致命错误——对端排队时
  // 解出 rank 并作为 UploadQueued{rank} 成功返回, 由调用方决定是否继续等待。仅 start_upload
  // 使用此路径; pump_until 对其余调用方(handshake/hashset 等)的 QUEUERANKING 语义保持不变。
  asio::awaitable<tl::expected<UploadOutcome,std::error_code>>
    pump_until_upload_result(std::chrono::milliseconds budget);

  asio::any_io_executor ex;
  std::optional<IPv4> remote;
  std::shared_ptr<const infra::IPFilter> ip_filter;
  std::uint8_t ip_filter_level = 127;
  Stream stream;
};

C2CConnection::C2CConnection(asio::any_io_executor ex) : impl_(std::make_unique<Impl>(ex)) {}
C2CConnection::C2CConnection(asio::ip::tcp::socket&& s) : impl_(std::make_unique<Impl>(std::move(s))) {}
C2CConnection::C2CConnection(net::EncryptedStreamSocket&& stream, std::optional<IPv4> remote)
  : impl_(std::make_unique<Impl>(std::move(stream), std::move(remote))) {}
C2CConnection::~C2CConnection() = default;
C2CConnection::C2CConnection(C2CConnection&&) noexcept = default;
C2CConnection& C2CConnection::operator=(C2CConnection&&) noexcept = default;

void C2CConnection::close() noexcept { impl_->close(); }
bool C2CConnection::encrypted() const noexcept { return impl_->encrypted(); }
asio::awaitable<tl::expected<void,std::error_code>>
C2CConnection::send_packet(const net::Packet& packet) { co_return co_await impl_->send(packet); }
asio::awaitable<tl::expected<net::Packet,std::error_code>>
C2CConnection::recv_packet(std::chrono::milliseconds timeout) { co_return co_await impl_->recv(timeout); }
asio::any_io_executor C2CConnection::executor() { return impl_->ex; }
std::optional<IPv4> C2CConnection::remote_ip() const { return impl_->remote; }
void C2CConnection::set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level) {
  impl_->ip_filter = std::move(filter);
  impl_->ip_filter_level = level;
  if (auto* plain = std::get_if<net::Connection>(&impl_->stream))
    plain->set_ip_filter(impl_->ip_filter, level);
}

asio::awaitable<tl::expected<void,std::error_code>>
C2CConnection::connect(IPv4 ip, std::uint16_t port, std::chrono::milliseconds timeout){
  const auto host = ip.host();
  const auto wire = ((host & 0xFFu) << 24) | ((host & 0xFF00u) << 8) |
                    ((host & 0xFF0000u) >> 8) | ((host & 0xFF000000u) >> 24);
  co_return co_await connect(PeerIdentity{{wire, port}, std::nullopt},
                             ObfuscationPolicy::disabled, timeout);
}

asio::awaitable<tl::expected<void,std::error_code>>
C2CConnection::connect(const PeerIdentity& peer, ObfuscationPolicy policy,
                       std::chrono::milliseconds timeout) {
  const auto deadline = clock_type::now() + timeout;
  if (peer.endpoint.low_id())
    co_return tl::unexpected(make_error_code(errc::connect_failed));
  const auto ip = IPv4::from_wire(peer.endpoint.id);
  if (impl_->ip_filter && impl_->ip_filter->blocked(ip, impl_->ip_filter_level))
    co_return tl::unexpected(make_error_code(errc::ip_filtered));
  if (policy == ObfuscationPolicy::required && !peer.user_hash)
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));

  impl_->remote = ip;
  if (policy != ObfuscationPolicy::disabled && peer.user_hash) {
    impl_->reset_encrypted();
    auto& encrypted = std::get<net::EncryptedStreamSocket>(impl_->stream);
    auto budget = remaining(deadline);
    if (!budget) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto connected = co_await encrypted.connect(ip, peer.endpoint.port, *budget);
    if (!connected)
      co_return tl::unexpected(connected.error());
    budget = remaining(deadline);
    if (!budget) co_return tl::unexpected(make_error_code(errc::timed_out));
    const auto negotiation_budget = policy == ObfuscationPolicy::preferred
        ? preferred_negotiation_budget(*budget) : *budget;
    auto negotiated = co_await encrypted.handshake_initiator(*peer.user_hash, negotiation_budget);
    if (negotiated) co_return tl::expected<void,std::error_code>{};
    encrypted.close();
    if (policy == ObfuscationPolicy::required)
      co_return tl::unexpected(negotiated.error());
  }

  impl_->reset_plain();
  auto& plain = std::get<net::Connection>(impl_->stream);
  plain.set_ip_filter(impl_->ip_filter, impl_->ip_filter_level);
  auto budget = remaining(deadline);
  if (!budget) co_return tl::unexpected(make_error_code(errc::timed_out));
  co_return co_await plain.connect(ip, peer.endpoint.port, *budget);
}

asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
C2CConnection::Impl::pump_until(std::uint8_t want, std::chrono::milliseconds budget, std::optional<std::uint8_t> protocol){
  auto deadline = clock_type::now() + budget;
  while(true){
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if(rem.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto rp = co_await recv(rem);
    if(!rp) co_return tl::unexpected(rp.error());
    auto pkt = std::move(*rp);
    if(pkt.opcode == want && (!protocol || pkt.protocol == *protocol)) co_return std::move(pkt);
    if(pkt.opcode == ed2k::peer::op::QUEUERANKING) co_return tl::unexpected(make_error_code(errc::upload_queued));
    if(pkt.opcode == ed2k::peer::op::FILEREQANSNOFIL) co_return tl::unexpected(make_error_code(errc::file_not_found));
    continue;
  }
}

asio::awaitable<tl::expected<UploadOutcome,std::error_code>>
C2CConnection::Impl::pump_until_upload_result(std::chrono::milliseconds budget){
  auto deadline = clock_type::now() + budget;
  while(true){
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if(rem.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto rp = co_await recv(rem);
    if(!rp) co_return tl::unexpected(rp.error());
    auto pkt = std::move(*rp);
    if(pkt.opcode == ed2k::peer::op::ACCEPTUPLOADREQ) co_return UploadOutcome{UploadAccepted{}};
    if(pkt.opcode == ed2k::peer::op::QUEUERANKING){
      auto rank = decode_queue_ranking(pkt.payload);
      if(!rank) co_return tl::unexpected(rank.error());
      co_return UploadOutcome{UploadQueued{*rank}};
    }
    if(pkt.opcode == ed2k::peer::op::FILEREQANSNOFIL) co_return tl::unexpected(make_error_code(errc::file_not_found));
    continue;
  }
}

asio::awaitable<tl::expected<HelloInfo,std::error_code>>
C2CConnection::handshake(const HelloInfo& mine, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::HELLO; req.payload=encode_hello_packet(mine);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::HELLOANSWER, timeout, ed2k::net::proto::eDonkey);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_hello_answer(rp->payload);
}
asio::awaitable<tl::expected<C2CHandshakeResult,std::error_code>>
C2CConnection::handshake_with_mule_info(const HelloInfo& mine, const MuleInfo& mule_info, std::chrono::milliseconds timeout){
  auto hello = co_await handshake(mine, timeout);
  if(!hello) co_return tl::unexpected(hello.error());
  // eMule 扩展信息交换是可选的: 纯 eDonkey 对端不支持 EMULEINFO/EMULEINFOANSWER, 交换会超时
  // 或失败——这不应使已经成功的 HELLO 握手失败, 仅 mule_info 退化为默认值 (udp_port=0,
  // Task 2: 下载侧据此退化为纯 TCP 被动等 ACCEPTUPLOADREQ, 不发 UDP reask)。
  // P0 架构决策#2: 该子步只等 min(timeout, kMuleHandshakeTimeout), 不占用调用方传入的完整
  // per-op 预算——把"纯 eDonkey 税"控制在小范围内 (调用方本就传入更短 timeout 时不受影响)。
  auto mule = co_await exchange_mule_info(mule_info, std::min(timeout, kMuleHandshakeTimeout));
  if(mule) co_return C2CHandshakeResult{std::move(*hello), std::move(*mule)};
  co_return C2CHandshakeResult{std::move(*hello), MuleInfo{}};
}
asio::awaitable<tl::expected<HelloInfo,std::error_code>>
C2CConnection::handshake_acceptor(const HelloInfo& mine, std::chrono::milliseconds timeout){
  // acceptor: peer (TCP initiator) sends HELLO first; we decode it then reply HELLOANSWER.
  // HELLO 与 HELLOANSWER 不对称: HELLO 前导 0x10 hashsize 字节, HELLOANSWER 无前导(aMule BaseClient.cpp)。
  // 故对端 HELLO 用 decode_hello(校验并跳过 0x10);我方 HELLOANSWER 用 encode_hello(无前导)。
  auto rp = co_await impl_->pump_until(op::HELLO, timeout, ed2k::net::proto::eDonkey);
  if(!rp) co_return tl::unexpected(rp.error());
  auto peer = decode_hello(rp->payload);
  if(!peer) co_return tl::unexpected(peer.error());
  ed2k::net::Packet ans; ans.protocol=ed2k::net::proto::eDonkey; ans.opcode=op::HELLOANSWER; ans.payload=encode_hello(mine);
  auto sr = co_await impl_->send(ans);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return std::move(*peer);
}
asio::awaitable<tl::expected<C2CHandshakeResult,std::error_code>>
C2CConnection::handshake_acceptor_with_mule_info(const HelloInfo& mine, const MuleInfo& mule_info, std::chrono::milliseconds timeout){
  auto rp = co_await impl_->pump_until(op::HELLO, timeout, ed2k::net::proto::eDonkey);
  if(!rp) co_return tl::unexpected(rp.error());
  auto peer = decode_hello(rp->payload);
  if(!peer) co_return tl::unexpected(peer.error());
  ed2k::net::Packet ans; ans.protocol=ed2k::net::proto::eDonkey; ans.opcode=op::HELLOANSWER; ans.payload=encode_hello(mine);
  auto sr = co_await impl_->send(ans);
  if(!sr) co_return tl::unexpected(sr.error());

  // eMule 扩展信息交换是可选的 (对称于 handshake_with_mule_info): 对端 (回调拨入的源) 若是纯
  // eDonkey 客户端, 不会主动发 EMULEINFO——等待超时或解码/应答失败均不应使已经成功的 HELLO
  // 握手失败, 仅 mule_info 退化为默认值 (udp_port=0)。
  // P0 架构决策#2: 同 handshake_with_mule_info, 该子步只等 min(timeout, kMuleHandshakeTimeout)。
  auto mule_req = co_await impl_->pump_until(op::EMULEINFO, std::min(timeout, kMuleHandshakeTimeout),
                                             ed2k::net::proto::eMule);
  if(!mule_req) co_return C2CHandshakeResult{std::move(*peer), MuleInfo{}};
  auto peer_mule = decode_mule_info(mule_req->payload);
  if(!peer_mule) co_return C2CHandshakeResult{std::move(*peer), MuleInfo{}};
  ed2k::net::Packet mule_ans; mule_ans.protocol=ed2k::net::proto::eMule; mule_ans.opcode=op::EMULEINFOANSWER; mule_ans.payload=encode_mule_info(mule_info);
  auto msr = co_await impl_->send(mule_ans);
  if(!msr) co_return C2CHandshakeResult{std::move(*peer), MuleInfo{}};
  co_return C2CHandshakeResult{std::move(*peer), std::move(*peer_mule)};
}
asio::awaitable<tl::expected<MuleInfo,std::error_code>>
C2CConnection::exchange_mule_info(const MuleInfo& mine, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eMule; req.opcode=op::EMULEINFO; req.payload=encode_mule_info(mine);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::EMULEINFOANSWER, timeout, ed2k::net::proto::eMule);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_mule_info(rp->payload);
}
asio::awaitable<tl::expected<FileStatus,std::error_code>>
C2CConnection::request_file(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::SETREQFILEID; req.payload=encode_set_req_file(h);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::FILESTATUS, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_file_status(rp->payload);
}
asio::awaitable<tl::expected<std::vector<PartHash>,std::error_code>>
C2CConnection::request_hashset(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::HASHSETREQUEST; req.payload=encode_hashset_request(h);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::HASHSETANSWER, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_hashset_answer(h, rp->payload);
}
asio::awaitable<tl::expected<std::string,std::error_code>>
C2CConnection::request_filename(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::REQUESTFILENAME; req.payload=encode_request_filename(h);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::REQFILENAMEANSWER, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  auto a = decode_req_filename_answer(rp->payload);
  if(!a) co_return tl::unexpected(a.error());
  co_return std::move(a->name);
}
asio::awaitable<tl::expected<UploadOutcome,std::error_code>>
C2CConnection::start_upload(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::STARTUPLOADREQ; req.payload=encode_start_upload(h);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return co_await impl_->pump_until_upload_result(timeout);
}
asio::awaitable<tl::expected<UploadOutcome,std::error_code>>
C2CConnection::wait_upload_outcome(std::chrono::milliseconds timeout){
  co_return co_await impl_->pump_until_upload_result(timeout);
}
asio::awaitable<tl::expected<std::vector<Block>,std::error_code>>
C2CConnection::request_blocks(const FileHash& h, std::array<std::uint32_t,3> starts, std::array<std::uint32_t,3> ends, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::REQUESTPARTS; req.payload=encode_request_parts(h, starts, ends);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return co_await accumulate_blocks(*impl_, h,
    std::array<std::uint64_t,3>{starts[0], starts[1], starts[2]},
    std::array<std::uint64_t,3>{ends[0], ends[1], ends[2]},
    op::SENDINGPART, op::COMPRESSEDPART,
    [](std::span<const std::byte> p) { return decode_sending_part(p); },
    [](std::span<const std::byte> p) { return decode_compressed_part_segment(p); },
    timeout);
}

asio::awaitable<tl::expected<std::vector<Block>,std::error_code>>
C2CConnection::request_blocks_i64(const FileHash& h, std::array<std::uint64_t,3> starts, std::array<std::uint64_t,3> ends, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eMule; req.opcode=op::REQUESTPARTS_I64; req.payload=encode_request_parts_i64(h, starts, ends);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return co_await accumulate_blocks(*impl_, h, starts, ends,
    op::SENDINGPART_I64, op::COMPRESSEDPART_I64,
    [](std::span<const std::byte> p) { return decode_sending_part_i64(p); },
    [](std::span<const std::byte> p) { return decode_compressed_part_i64_segment(p); },
    timeout);
}

asio::awaitable<tl::expected<AICHHash,std::error_code>>
C2CConnection::request_aich_master_hash(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eMule; req.opcode=op::AICHFILEHASHREQ;
  req.payload=encode_aich_file_hash_req(h);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::AICHFILEHASHANS, timeout, ed2k::net::proto::eMule);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_aich_file_hash_ans(rp->payload);
}

asio::awaitable<tl::expected<SourceExchangeAnswer,std::error_code>>
C2CConnection::request_sources2(const FileHash& h, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eMule; req.opcode=op::MULTIPACKET;
  req.payload=encode_multipacket_request_sources2(h);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::ANSWERSOURCES2, timeout, ed2k::net::proto::eMule);
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
  co_return co_await impl_->send(req);
}

asio::awaitable<tl::expected<AICHRecoveryData,std::error_code>>
C2CConnection::request_aich_proof(const FileHash& h, const AICHHash& master, std::uint16_t part_index, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eMule; req.opcode=op::AICHREQUEST;
  req.payload=encode_aich_request(h, master, part_index);
  auto sr = co_await impl_->send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::AICHANSWER, timeout, ed2k::net::proto::eMule);
  if(!rp) co_return tl::unexpected(rp.error());
  // 校验回显的 master_hash 与请求一致 (aMule DownloadClient.cpp:1634 ahMasterHash == GetMasterHash):
  // 帧 = file_hash(16) + part_index(2) + master_hash(20) + V2 data,master_hash 在偏移 18..38。
  {
    codec::ByteReader r(rp->payload);
    (void)r.hash16();                    // file_hash(16)
    (void)r.u16();                       // part_index(2)
    auto echoed = AICHHash::from_bytes(r.hash20());
    if(!r.ok() || echoed != master) co_return tl::unexpected(make_error_code(errc::hash_mismatch));
  }
  co_return decode_aich_answer(rp->payload);
}
}
