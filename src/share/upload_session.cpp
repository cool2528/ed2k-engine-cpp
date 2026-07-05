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
                             ClientCredits* credits)
  : conn_(std::move(socket)),
    files_(files),
    self_(std::move(self)),
    disk_executor_(std::move(disk_executor)),
    queue_(queue),
    throttler_(throttler),
    credits_(credits) {}

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::handshake(std::chrono::milliseconds timeout) {
  auto rp = co_await conn_.recv(timeout);
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
  auto sr = co_await conn_.send(ans);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::send_not_found(const ed2k::FileHash& hash) {
  ed2k::net::Packet ans;
  ans.protocol = ed2k::net::proto::eDonkey;
  ans.opcode = ed2k::peer::op::FILEREQANSNOFIL;
  ans.payload = ed2k::peer::encode_set_req_file(hash);
  co_return co_await conn_.send(ans);
}

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::handle(const ed2k::net::Packet& pkt) {
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
    co_return co_await conn_.send(ans);
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
    co_return co_await conn_.send(ans);
  }

  if(pkt.opcode == ed2k::peer::op::FILEDESC) {
    auto decoded = ed2k::peer::decode_file_desc(pkt.payload);
    if(!decoded) co_return tl::unexpected(decoded.error());
    if(current_file_) files_.set_file_desc(*current_file_, decoded->rating, std::move(decoded->comment));
    co_return tl::expected<void, std::error_code>{};
  }

  if(pkt.opcode == ed2k::peer::op::STARTUPLOADREQ) {
    auto decoded = ed2k::peer::decode_file_hash_request(pkt.payload);
    if(!decoded) co_return tl::unexpected(decoded.error());
    const KnownFile* file = files_.find(*decoded);
    if(!file) co_return co_await send_not_found(*decoded);

    ed2k::net::Packet ans;
    ans.protocol = ed2k::net::proto::eDonkey;
    if(!queue_ || !peer_) {
      ans.opcode = ed2k::peer::op::ACCEPTUPLOADREQ;
    } else {
      auto decision = queue_->enqueue(peer_->user_hash, *decoded);
      if(decision.state == UploadQueueState::accepted) {
        ans.opcode = ed2k::peer::op::ACCEPTUPLOADREQ;
      } else {
        ans.opcode = ed2k::peer::op::QUEUERANKING;
        ans.payload = ed2k::peer::encode_queue_ranking(decision.rank);
      }
    }
    co_return co_await conn_.send(ans);
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
    co_return co_await conn_.send(ans);
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
    co_return co_await conn_.send(ans);
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

  auto sr = co_await conn_.send(ans);
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
  for(std::size_t i = 0; i < req.starts.size(); ++i) {
    std::uint64_t cur = req.starts[i];
    const std::uint64_t end = req.ends[i];
    if(cur >= end) continue;
    while(cur < end) {
      const std::uint64_t chunk_end = std::min<std::uint64_t>(cur + sending_part_chunk_size, end);
      auto data = co_await read_range(file, cur, chunk_end);
      if(!data) co_return tl::unexpected(data.error());
      ed2k::net::Packet ans;
      ans.protocol = ed2k::net::proto::eDonkey;
      ans.opcode = ed2k::peer::op::SENDINGPART;
      ans.payload = ed2k::peer::encode_sending_part(req.hash, cur, *data);
      if(throttler_) co_await throttler_->acquire(data->size());
      auto sr = co_await conn_.send(ans);
      if(!sr) co_return tl::unexpected(sr.error());
      if(credits_ && peer_) credits_->add_uploaded(peer_->user_hash, data->size());
      cur = chunk_end;
    }
  }
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::run(std::chrono::milliseconds timeout) {
  auto hs = co_await handshake(timeout);
  if(!hs) co_return tl::unexpected(hs.error());
  while(true) {
    auto rp = co_await conn_.recv(timeout);
    if(!rp) {
      if(rp.error() == make_error_code(errc::connection_closed)) {
        if(queue_ && peer_) queue_->remove(peer_->user_hash);
        co_return tl::expected<void, std::error_code>{};
      }
      co_return tl::unexpected(rp.error());
    }
    auto hr = co_await handle(*rp);
    if(!hr) co_return tl::unexpected(hr.error());
  }
}

} // namespace ed2k::share
