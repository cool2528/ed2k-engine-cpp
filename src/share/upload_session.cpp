#include "ed2k/share/upload_session.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/crypto/sha1.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/peer/c2c_opcodes.hpp"
#include "ed2k/util/error.hpp"
#include <algorithm>
#include <fstream>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace ed2k::share {
namespace asio = boost::asio;
namespace {
constexpr std::uint64_t sending_part_chunk_size = 10240;
constexpr std::uint64_t preview_frame_size = 256ull * 1024ull;
// P2c A8: run() 排队态短轮询间隔(见 run() 实现注释)。刻意与下载侧 kReaskInterval(60s)/
// kUploadQueuePollInterval 各自独立解耦——这里只是"多快检查一次自己是否轮到了", 不是协议往返
// 预算, 取值参考本文件既有惯例(session.cpp accept_loop 1s、InboundListener kAcceptPollSlice
// 20ms)——150ms 足够快地发现槽位释放, 又不至于空转过密。
constexpr std::chrono::milliseconds kUploadQueuePollInterval{150};
using Digest = std::array<std::byte, 20>;

Digest sha1_cat(const Digest& l, const Digest& r) {
  ed2k::crypto::SHA1 h;
  h.update(l);
  h.update(r);
  return h.finish();
}

struct Split { std::uint64_t n_left, n_right, base_left, base_right; };
Split split_children(std::uint64_t n, std::uint64_t base, bool is_left) {
  std::uint64_t n_blocks = n / base + ((n % base) != 0 ? 1 : 0);
  std::uint64_t n_left = ((is_left ? n_blocks + 1 : n_blocks) / 2) * base;
  std::uint64_t n_right = n - n_left;
  std::uint64_t bl = (n_left <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  std::uint64_t br = (n_right <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  return {n_left, n_right, bl, br};
}

Digest subtree_root(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left) {
  if(n <= base) return ed2k::crypto::sha1(d.first(static_cast<std::size_t>(n)));
  auto s = split_children(n, base, is_left);
  return sha1_cat(subtree_root(d.first(static_cast<std::size_t>(s.n_left)), s.n_left, s.base_left, true),
                  subtree_root(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false));
}

void collect_leaves(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left,
                    std::uint32_t ident, std::vector<ed2k::peer::AICHProofHash>& out) {
  if(n <= base) {
    ed2k::peer::AICHProofHash p;
    p.identifier = ident;
    p.hash = ed2k::crypto::sha1(d.first(static_cast<std::size_t>(n)));
    out.push_back(p);
    return;
  }
  auto s = split_children(n, base, is_left);
  collect_leaves(d.first(static_cast<std::size_t>(s.n_left)), s.n_left, s.base_left, true, (ident << 1) | 1, out);
  collect_leaves(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false, ident << 1, out);
}

void collect_recovery(std::span<const std::byte> d, std::uint64_t n, std::uint64_t base, bool is_left,
                      std::uint32_t ident, std::uint64_t part_off, std::uint64_t part_size,
                      std::vector<ed2k::peer::AICHProofHash>& out) {
  if(part_off == 0 && part_size == n) {
    collect_leaves(d, n, base, is_left, ident, out);
    return;
  }
  auto s = split_children(n, base, is_left);
  const std::uint32_t left_ident = (ident << 1) | 1;
  const std::uint32_t right_ident = ident << 1;
  if(part_off < s.n_left) {
    ed2k::peer::AICHProofHash p;
    p.identifier = right_ident;
    p.hash = subtree_root(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false);
    out.push_back(p);
    collect_recovery(d.first(static_cast<std::size_t>(s.n_left)), s.n_left, s.base_left, true,
                     left_ident, part_off, part_size, out);
  } else {
    ed2k::peer::AICHProofHash p;
    p.identifier = left_ident;
    p.hash = subtree_root(d.first(static_cast<std::size_t>(s.n_left)), s.n_left, s.base_left, true);
    out.push_back(p);
    collect_recovery(d.subspan(static_cast<std::size_t>(s.n_left)), s.n_right, s.base_right, false,
                     right_ident, part_off - s.n_left, part_size, out);
  }
}

tl::expected<std::vector<ed2k::peer::AICHProofHash>, std::error_code>
recovery_for(std::span<const std::byte> full, std::uint16_t part_index) {
  if(full.empty()) return tl::unexpected(make_error_code(errc::io_error));
  const std::uint64_t n = static_cast<std::uint64_t>(full.size());
  const std::uint64_t pstart = static_cast<std::uint64_t>(part_index) * PART_SIZE;
  if(pstart >= n) return tl::unexpected(make_error_code(errc::io_error));
  const std::uint64_t psize = std::min(PART_SIZE, n - pstart);
  const std::uint64_t root_base = (n <= PART_SIZE) ? static_cast<std::uint64_t>(AICH_BLOCK_SIZE) : PART_SIZE;
  std::vector<ed2k::peer::AICHProofHash> out;
  collect_recovery(full, n, root_base, true, 1, pstart, psize, out);
  return out;
}
}

UploadSession::UploadSession(ed2k::peer::C2CConnection&& connection,
                             KnownFileDB& files,
                             ed2k::peer::HelloInfo self)
  : conn_(std::move(connection)), files_(files), self_(std::move(self)),
    disk_executor_(conn_.executor()) {}

UploadSession::UploadSession(ed2k::peer::C2CConnection&& connection,
                             KnownFileDB& files,
                             ed2k::peer::HelloInfo self,
                             asio::any_io_executor disk_executor,
                             UploadQueue* queue,
                             UploadBandwidthThrottler* throttler,
                             ClientCredits* credits)
  : conn_(std::move(connection)), files_(files), self_(std::move(self)),
    disk_executor_(std::move(disk_executor)), queue_(queue), throttler_(throttler), credits_(credits) {}

UploadSession::UploadSession(asio::ip::tcp::socket&& socket,
                             KnownFileDB& files,
                             ed2k::peer::HelloInfo self)
  : conn_(std::move(socket)), files_(files), self_(std::move(self)), disk_executor_(conn_.executor()) {}

UploadSession::UploadSession(asio::ip::tcp::socket&& socket,
                             KnownFileDB& files,
                             ed2k::peer::HelloInfo self,
                             asio::any_io_executor disk_executor)
  : conn_(std::move(socket)), files_(files), self_(std::move(self)), disk_executor_(std::move(disk_executor)) {}

UploadSession::UploadSession(asio::ip::tcp::socket&& socket,
                             KnownFileDB& files,
                             ed2k::peer::HelloInfo self,
                             asio::any_io_executor disk_executor,
                             UploadQueue* queue)
  : conn_(std::move(socket)),
    files_(files),
    self_(std::move(self)),
    disk_executor_(std::move(disk_executor)),
    queue_(queue) {}

UploadSession::UploadSession(asio::ip::tcp::socket&& socket,
                             KnownFileDB& files,
                             ed2k::peer::HelloInfo self,
                             asio::any_io_executor disk_executor,
                             UploadQueue* queue,
                             UploadBandwidthThrottler* throttler)
  : conn_(std::move(socket)),
    files_(files),
    self_(std::move(self)),
    disk_executor_(std::move(disk_executor)),
    queue_(queue),
    throttler_(throttler) {}

UploadSession::UploadSession(asio::ip::tcp::socket&& socket,
                             KnownFileDB& files,
                             ed2k::peer::HelloInfo self,
                             asio::any_io_executor disk_executor,
                             UploadQueue* queue,
                             UploadBandwidthThrottler* throttler,
                             ClientCredits* credits,
                             std::uint16_t udp_reask_port)
  : conn_(std::move(socket)),
    files_(files),
    self_(std::move(self)),
    disk_executor_(std::move(disk_executor)),
    queue_(queue),
    throttler_(throttler),
    credits_(credits),
    udp_reask_port_(udp_reask_port) {}

void UploadSession::set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level) {
  ip_filter_ = std::move(filter);
  ip_filter_level_ = level;
}

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::handshake(std::chrono::milliseconds timeout) {
  auto rp = co_await conn_.recv_packet(timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  if(rp->opcode != ed2k::peer::op::HELLO)
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  auto peer = ed2k::peer::decode_hello(rp->payload);
  if(!peer) co_return tl::unexpected(peer.error());
  peer_ = *peer;
  ed2k::net::Packet ans;
  ans.protocol = ed2k::net::proto::eDonkey;
  ans.opcode = ed2k::peer::op::HELLOANSWER;
  ans.payload = ed2k::peer::encode_hello(self_);
  auto sr = co_await conn_.send_packet(ans);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::send_not_found(const ed2k::FileHash& hash) {
  ed2k::net::Packet ans;
  ans.protocol = ed2k::net::proto::eDonkey;
  ans.opcode = ed2k::peer::op::FILEREQANSNOFIL;
  ans.payload = ed2k::peer::encode_set_req_file(hash);
  co_return co_await conn_.send_packet(ans);
}

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::handle(const ed2k::net::Packet& pkt) {
  // P2c A8: 应答对端(下载方)在 HELLO/HELLOANSWER 之后可能发来的 EMULEINFO, 通告我方真实的
  // UDP reask 端口(udp_reask_port_)。刻意实现为 handle() 里"这个 opcode 就这么处理"的一条
  // 普通分支, 而不是像 handshake_with_mule_info/handshake_acceptor_with_mule_info 那样在
  // 握手内部专门 pump_until(EMULEINFO, kMuleHandshakeTimeout) 阻塞等待——那样做会在"对端根本
  // 不发 EMULEINFO"的场景(既有测试大量使用的裸 HELLO 客户端)里, 把对端紧随其后发来的下一个
  // 真实请求包(如 STARTUPLOADREQ)当"等待期间的噪声"静默吞掉, 直到整个 mule 子步超时才继续,
  // 拖慢且破坏既有测试的握手后第一包语义。现在的写法:发不发 EMULEINFO 都不影响后续任何一个
  // 包的处理顺序, 对端不发就什么都不做(udp_port 由对端保持默认值 0, 优雅降级为纯 TCP 被动)。
  if(pkt.opcode == ed2k::peer::op::EMULEINFO && pkt.protocol == ed2k::net::proto::eMule) {
    ed2k::peer::MuleInfo mine;
    mine.udp_port = udp_reask_port_;
    ed2k::net::Packet ans;
    ans.protocol = ed2k::net::proto::eMule;
    ans.opcode = ed2k::peer::op::EMULEINFOANSWER;
    ans.payload = ed2k::peer::encode_mule_info(mine);
    co_return co_await conn_.send_packet(ans);
  }

  if(pkt.opcode == ed2k::peer::op::MULTIPACKET || pkt.opcode == ed2k::peer::op::MULTIPACKET_EXT) {
    ed2k::codec::ByteReader r(pkt.payload);
    auto hash = r.hash16();
    const auto advertised_size = pkt.opcode == ed2k::peer::op::MULTIPACKET_EXT ? r.u64() : 0;
    (void)advertised_size;
    if(!r.ok()) co_return tl::unexpected(make_error_code(errc::buffer_underflow));

    const KnownFile* file = files_.find(hash);
    if(!file) co_return co_await send_not_found(hash);
    current_file_ = hash;

    while(r.remaining() > 0 && r.ok()) {
      const auto subop = r.u8();
      ed2k::net::Packet ans;
      switch(subop) {
        case ed2k::peer::op::REQUESTFILENAME:
          ans.protocol = ed2k::net::proto::eDonkey;
          ans.opcode = ed2k::peer::op::REQFILENAMEANSWER;
          ans.payload = ed2k::peer::encode_req_filename_answer(hash, file->name);
          break;
        case ed2k::peer::op::SETREQFILEID:
          ans.protocol = ed2k::net::proto::eDonkey;
          ans.opcode = ed2k::peer::op::FILESTATUS;
          ans.payload = ed2k::peer::encode_file_status(hash, {});
          break;
        case ed2k::peer::op::AICHFILEHASHREQ:
          ans.protocol = ed2k::net::proto::eMule;
          ans.opcode = ed2k::peer::op::AICHFILEHASHANS;
          ans.payload = ed2k::peer::encode_aich_file_hash_ans(hash, file->aich_root);
          break;
        case ed2k::peer::op::REQUESTSOURCES2: {
          const auto requested_version = r.u8();
          const auto requested_options = r.u16();
          (void)requested_options;
          if(!r.ok()) co_return tl::unexpected(make_error_code(errc::buffer_underflow));
          ans.protocol = ed2k::net::proto::eMule;
          ans.opcode = ed2k::peer::op::ANSWERSOURCES2;
          ans.payload = ed2k::peer::encode_answer_sources2(
            hash, file->sources, std::min<std::uint8_t>(requested_version ? requested_version : 4, 4));
          break;
        }
        default:
          co_return tl::expected<void, std::error_code>{};
      }
      auto sr = co_await conn_.send_packet(ans);
      if(!sr) co_return tl::unexpected(sr.error());
    }
    if(!r.ok()) co_return tl::unexpected(make_error_code(errc::buffer_underflow));
    co_return tl::expected<void, std::error_code>{};
  }

  if(pkt.opcode == ed2k::peer::op::ASKSHAREDFILES) {
    std::vector<ed2k::peer::SharedFileEntry> entries;
    entries.reserve(files_.files().size());
    for(const auto& file : files_.files()) {
      entries.push_back({file.hash, self_.client_id, self_.port});
    }
    ed2k::net::Packet ans;
    ans.protocol = ed2k::net::proto::eDonkey;
    ans.opcode = ed2k::peer::op::ASKSHAREDFILESANSWER;
    ans.payload = ed2k::peer::encode_shared_files_answer(entries);
    co_return co_await conn_.send_packet(ans);
  }

  if(pkt.opcode == ed2k::peer::op::REQUESTSOURCES2) {
    auto decoded = ed2k::peer::decode_request_sources2(pkt.payload);
    if(!decoded) co_return tl::unexpected(decoded.error());
    const KnownFile* file = files_.find(*decoded);
    if(!file) co_return co_await send_not_found(*decoded);
    ed2k::net::Packet ans;
    ans.protocol = ed2k::net::proto::eMule;
    ans.opcode = ed2k::peer::op::ANSWERSOURCES2;
    ans.payload = ed2k::peer::encode_answer_sources2(file->hash, file->sources);
    co_return co_await conn_.send_packet(ans);
  }

  if(pkt.opcode == ed2k::peer::op::FILEDESC) {
    auto decoded = ed2k::peer::decode_file_desc(pkt.payload);
    if(!decoded) co_return tl::unexpected(decoded.error());
    if(current_file_) files_.set_file_desc(*current_file_, decoded->rating, std::move(decoded->comment));
    co_return tl::expected<void, std::error_code>{};
  }

  if(pkt.opcode == ed2k::peer::op::REQUESTPREVIEW) {
    auto decoded = ed2k::peer::decode_file_hash_request(pkt.payload);
    if(!decoded) co_return tl::unexpected(decoded.error());
    const KnownFile* file = files_.find(*decoded);
    if(!file) co_return co_await send_not_found(*decoded);
    auto data = co_await read_range(*file, 0, std::min<std::uint64_t>(file->size, preview_frame_size));
    if(!data) co_return tl::unexpected(data.error());
    const std::array<std::span<const std::byte>, 1> frames{std::span<const std::byte>(*data)};
    ed2k::net::Packet ans;
    ans.protocol = ed2k::net::proto::eMule;
    ans.opcode = ed2k::peer::op::PREVIEWANSWER;
    ans.payload = ed2k::peer::encode_preview_answer(*decoded, frames);
    co_return co_await conn_.send_packet(ans);
  }

  if(pkt.opcode == ed2k::peer::op::STARTUPLOADREQ) {
    auto decoded = ed2k::peer::decode_file_hash_request(pkt.payload);
    if(!decoded) co_return tl::unexpected(decoded.error());
    const KnownFile* file = files_.find(*decoded);
    if(!file) co_return co_await send_not_found(*decoded);
    files_.note_request(*decoded);  // 每文件请求数统计

    ed2k::net::Packet ans;
    ans.protocol = ed2k::net::proto::eDonkey;
    if(!queue_ || !peer_) {
      ans.opcode = ed2k::peer::op::ACCEPTUPLOADREQ;
      is_queued_ = false;
    } else {
      // ip 供 P2c A8 的 UDP REASKFILEPING 应答按 (ip, file_hash) 反查本条排队记录用(remote_ip()
      // 取不到时——非 IPv4/已断连——退化为默认 IPv4{}, 该记录只是暂时无法被 UDP reask 命中,
      // 不影响 TCP 侧 accepted/queued/full 判定本身)。
      auto decision = queue_->enqueue(peer_->user_hash, *decoded, conn_.remote_ip().value_or(IPv4{}));
      if(decision.state == UploadQueueState::accepted) {
        ans.opcode = ed2k::peer::op::ACCEPTUPLOADREQ;
        is_queued_ = false;
      } else if(decision.state == UploadQueueState::full) {
        // P2c A7: 队列已满——答 QUEUEFULL(与 UDP reask 侧同一 opcode/协议标记, 见
        // c2c_connection.cpp::pump_until_upload_result 的 UploadQueueFull 解码), 不入队、不占用
        // is_queued_ 轮询路径。
        ans.protocol = ed2k::net::proto::eMule;
        ans.opcode = ed2k::peer::op::QUEUEFULL;
        is_queued_ = false;
      } else {
        ans.opcode = ed2k::peer::op::QUEUERANKING;
        ans.payload = ed2k::peer::encode_queue_ranking(decision.rank);
        // P2c A8: 记住"排队中"状态与具体文件, 供 run() 主循环短轮询期间重新调用 queue_->enqueue()
        // 检查槽位是否已释放(见该函数注释)——这是让排队晋升在"没有任何一方重发 STARTUPLOADREQ/
        // 没有专门的跨协程通知通道"时依然会发生的唯一途径, 与 UDP reask 的到达与否解耦。
        is_queued_ = true;
        queued_hash_ = *decoded;
      }
    }
    co_return co_await conn_.send_packet(ans);
  }

  if(pkt.opcode == ed2k::peer::op::REQUESTPARTS) {
    auto decoded = ed2k::peer::decode_request_parts(pkt.payload);
    if(!decoded) co_return tl::unexpected(decoded.error());
    const KnownFile* file = files_.find(decoded->hash);
    if(!file) co_return co_await send_not_found(decoded->hash);
    co_return co_await send_requested_parts(*file, *decoded);
  }

  if(pkt.opcode == ed2k::peer::op::AICHFILEHASHREQ) {
    auto decoded = ed2k::peer::decode_file_hash_request(pkt.payload);
    if(!decoded) co_return tl::unexpected(decoded.error());
    const KnownFile* file = files_.find(*decoded);
    if(!file) co_return co_await send_not_found(*decoded);
    ed2k::net::Packet ans;
    ans.protocol = ed2k::net::proto::eMule;
    ans.opcode = ed2k::peer::op::AICHFILEHASHANS;
    ans.payload = ed2k::peer::encode_aich_file_hash_ans(*decoded, file->aich_root);
    co_return co_await conn_.send_packet(ans);
  }

  if(pkt.opcode == ed2k::peer::op::AICHREQUEST) {
    ed2k::codec::ByteReader r(pkt.payload);
    auto hash = r.hash16();
    const auto part_index = r.u16();
    const auto requested_master = ed2k::AICHHash::from_bytes(r.hash20());
    if(!r.ok()) co_return tl::unexpected(make_error_code(errc::buffer_underflow));
    const KnownFile* file = files_.find(hash);
    if(!file) co_return co_await send_not_found(hash);
    if(requested_master != file->aich_root) co_return tl::unexpected(make_error_code(errc::hash_mismatch));
    auto full = co_await read_range(*file, 0, file->size);
    if(!full) co_return tl::unexpected(full.error());
    auto proof = recovery_for(*full, part_index);
    if(!proof) co_return tl::unexpected(proof.error());
    ed2k::net::Packet ans;
    ans.protocol = ed2k::net::proto::eMule;
    ans.opcode = ed2k::peer::op::AICHANSWER;
    ans.payload = ed2k::peer::encode_aich_answer(hash, file->aich_root, part_index, *proof);
    co_return co_await conn_.send_packet(ans);
  }

  if(pkt.opcode != ed2k::peer::op::REQUESTFILENAME &&
     pkt.opcode != ed2k::peer::op::SETREQFILEID &&
     pkt.opcode != ed2k::peer::op::HASHSETREQUEST) {
    co_return tl::expected<void, std::error_code>{};
  }

  auto decoded = ed2k::peer::decode_file_hash_request(pkt.payload);
  if(!decoded) co_return tl::unexpected(decoded.error());
  const auto& hash = *decoded;
  const KnownFile* file = files_.find(hash);
  if(!file) co_return co_await send_not_found(hash);
  current_file_ = hash;

  ed2k::net::Packet ans;
  ans.protocol = ed2k::net::proto::eDonkey;
  switch(pkt.opcode) {
    case ed2k::peer::op::REQUESTFILENAME:
      ans.opcode = ed2k::peer::op::REQFILENAMEANSWER;
      ans.payload = ed2k::peer::encode_req_filename_answer(hash, file->name);
      break;
    case ed2k::peer::op::SETREQFILEID:
      ans.opcode = ed2k::peer::op::FILESTATUS;
      ans.payload = ed2k::peer::encode_file_status(hash, {});
      break;
    case ed2k::peer::op::HASHSETREQUEST:
      if(file->part_hashes.empty()) co_return tl::expected<void, std::error_code>{};
      ans.opcode = ed2k::peer::op::HASHSETANSWER;
      ans.payload = ed2k::peer::encode_hashset_answer(hash, file->part_hashes);
      break;
    default:
      co_return tl::expected<void, std::error_code>{};
  }

  auto sr = co_await conn_.send_packet(ans);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<std::vector<std::byte>, std::error_code>>
UploadSession::read_range(const KnownFile& file, std::uint64_t start, std::uint64_t end) {
  const auto net_executor = conn_.executor();
  co_await asio::post(disk_executor_, asio::bind_executor(disk_executor_, asio::use_awaitable));
  tl::expected<std::vector<std::byte>, std::error_code> result;
  if(start > end || end > file.size) {
    result = tl::unexpected(make_error_code(errc::io_error));
  } else {
    std::vector<std::byte> data(static_cast<std::size_t>(end - start));
    std::ifstream in(file.path, std::ios::binary);
    if(!in) {
      result = tl::unexpected(make_error_code(errc::io_error));
    } else {
      in.seekg(static_cast<std::streamoff>(start));
      in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
      if(static_cast<std::size_t>(in.gcount()) != data.size()) {
        result = tl::unexpected(make_error_code(errc::io_error));
      } else {
        result = std::move(data);
      }
    }
  }
  co_await asio::post(net_executor, asio::bind_executor(net_executor, asio::use_awaitable));
  co_return result;
}

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::send_requested_parts(const KnownFile& file, const ed2k::peer::RequestParts& req) {
  auto send_uncompressed = [&](std::uint64_t start, std::span<const std::byte> data)
      -> asio::awaitable<tl::expected<void, std::error_code>> {
    std::uint64_t cur = start;
    std::span<const std::byte> remaining = data;
    while(!remaining.empty()) {
      const auto n = std::min<std::uint64_t>(sending_part_chunk_size, remaining.size());
      auto chunk = remaining.first(static_cast<std::size_t>(n));
      ed2k::net::Packet ans;
      ans.protocol = ed2k::net::proto::eDonkey;
      ans.opcode = ed2k::peer::op::SENDINGPART;
      ans.payload = ed2k::peer::encode_sending_part(req.hash, cur, chunk);
      if(throttler_) co_await throttler_->acquire(chunk.size());
      auto sr = co_await conn_.send_packet(ans);
      if(!sr) co_return tl::unexpected(sr.error());
      if(credits_ && peer_) credits_->add_uploaded(peer_->user_hash, chunk.size());
      cur += n;
      remaining = remaining.subspan(static_cast<std::size_t>(n));
    }
    co_return tl::expected<void, std::error_code>{};
  };

  for(std::size_t i = 0; i < req.starts.size(); ++i) {
    std::uint64_t cur = req.starts[i];
    const std::uint64_t end = req.ends[i];
    if(cur >= end) continue;

    if(peer_ && peer_->supports_compression) {
      auto data = co_await read_range(file, cur, end);
      if(!data) co_return tl::unexpected(data.error());
      auto payload = ed2k::peer::encode_compressed_part(req.hash, cur, *data);
      auto segment = ed2k::peer::decode_compressed_part_segment(payload);
      if(!segment) co_return tl::unexpected(segment.error());
      const auto packed_size = segment->compressed_size;
      if(packed_size > 0 && packed_size < data->size()) {
        std::span<const std::byte> packed(segment->data.data(), segment->data.size());
        std::size_t offset = 0;
        while(offset < packed.size()) {
          const auto n = std::min<std::size_t>(static_cast<std::size_t>(sending_part_chunk_size), packed.size() - offset);
          ed2k::codec::ByteWriter w;
          w.hash16(req.hash);
          w.u32(static_cast<std::uint32_t>(cur));
          w.u32(packed_size);
          w.blob(packed.subspan(offset, n));
          ed2k::net::Packet ans;
          ans.protocol = ed2k::net::proto::eMule;
          ans.opcode = ed2k::peer::op::COMPRESSEDPART;
          ans.payload = w.take();
          if(throttler_) co_await throttler_->acquire(n);
          auto sr = co_await conn_.send_packet(ans);
          if(!sr) co_return tl::unexpected(sr.error());
          offset += n;
        }
        if(credits_ && peer_) credits_->add_uploaded(peer_->user_hash, data->size());
        continue;
      }

      auto sr = co_await send_uncompressed(cur, *data);
      if(!sr) co_return tl::unexpected(sr.error());
      continue;
    }

    while(cur < end) {
      const std::uint64_t chunk_end = std::min<std::uint64_t>(cur + sending_part_chunk_size, end);
      auto data = co_await read_range(file, cur, chunk_end);
      if(!data) co_return tl::unexpected(data.error());
      ed2k::net::Packet ans;
      ans.protocol = ed2k::net::proto::eDonkey;
      ans.opcode = ed2k::peer::op::SENDINGPART;
      ans.payload = ed2k::peer::encode_sending_part(req.hash, cur, *data);
      if(throttler_) co_await throttler_->acquire(data->size());
      auto sr = co_await conn_.send_packet(ans);
      if(!sr) co_return tl::unexpected(sr.error());
      if(credits_ && peer_) credits_->add_uploaded(peer_->user_hash, data->size());
      cur = chunk_end;
    }
  }
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::run(std::chrono::milliseconds timeout) {
  if (ip_filter_) {
    auto remote = conn_.remote_ip();
    if (remote && ip_filter_->blocked(*remote, ip_filter_level_)) {
      conn_.close();
      co_return tl::unexpected(make_error_code(errc::ip_filtered));
    }
  }
  auto hs = co_await handshake(timeout);
  if(!hs) co_return tl::unexpected(hs.error());
  while(true) {
    // P2c A8: 排队中(is_queued_)时把 recv_packet 的等待预算收紧为短轮询(kUploadQueuePollInterval)
    // ——不是为了收对端的包(排队期间对端不会重发 STARTUPLOADREQ, 只可能被动等或走 UDP reask),
    // 而是借每次超时的机会重新调用 queue_->enqueue() 检查槽位是否已释放。这是本引擎让"排队晋升"
    // 在没有专门跨协程通知通道时依然会发生的机制——与 D1 式等待者注册表不同, 这里不需要仲裁多个
    // 等待者, 单纯是"定期问一下自己是否轮到了", 故用最简单的短超时轮询(同 accept_loop/kad_run
    // 既有惯例), 不引入新的 channel/通知原语。非排队态行为与改动前完全一致(用调用方传入的完整
    // per-op timeout, 超时即视为连接层错误向上抛出)。
    const auto wait_budget = is_queued_ ? std::min(timeout, kUploadQueuePollInterval) : timeout;
    auto rp = co_await conn_.recv_packet(wait_budget);
    if(!rp) {
      if(rp.error() == make_error_code(errc::connection_closed)) {
        if(queue_ && peer_) queue_->remove(peer_->user_hash);
        co_return tl::expected<void, std::error_code>{};
      }
      if(is_queued_ && rp.error() == make_error_code(errc::timed_out)) {
        // 排队中的短轮询超时: 非致命, 重新检查槽位是否已释放; 若已晋升则主动下发 ACCEPTUPLOADREQ
        // (对端此刻可能正被动等 TCP、也可能正等 UDP REASKACK/下一轮再来问, 两者都不冲突: 已晋升
        // 之后再来的 REASKFILEPING 只会在 UDP 应答里看到同一个"已不在队列"结果, 见
        // session.cpp::udp_reask_loop 与 UploadQueue::find_queued 的语义)。
        if(queue_ && peer_ && queued_hash_) {
          auto decision = queue_->enqueue(peer_->user_hash, *queued_hash_);
          if(decision.state == UploadQueueState::accepted) {
            is_queued_ = false;
            ed2k::net::Packet ans;
            ans.protocol = ed2k::net::proto::eDonkey;
            ans.opcode = ed2k::peer::op::ACCEPTUPLOADREQ;
            auto sr = co_await conn_.send_packet(ans);
            if(!sr) co_return tl::unexpected(sr.error());
          }
        }
        continue;   // 本轮是超时, 没有真实的包需要交给 handle()
      }
      co_return tl::unexpected(rp.error());
    }
    auto hr = co_await handle(*rp);
    if(!hr) co_return tl::unexpected(hr.error());
  }
}

} // namespace ed2k::share
