#include "ed2k/share/upload_session.hpp"
#include "ed2k/peer/c2c_opcodes.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::share {
namespace asio = boost::asio;

UploadSession::UploadSession(asio::ip::tcp::socket&& socket,
                             const KnownFileDB& files,
                             ed2k::peer::HelloInfo self)
  : conn_(std::move(socket)), files_(files), self_(std::move(self)) {}

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::handshake(std::chrono::milliseconds timeout) {
  auto rp = co_await conn_.recv(timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  if(rp->opcode != ed2k::peer::op::HELLO)
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  auto peer = ed2k::peer::decode_hello(rp->payload);
  if(!peer) co_return tl::unexpected(peer.error());
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

asio::awaitable<tl::expected<void, std::error_code>>
UploadSession::run(std::chrono::milliseconds timeout) {
  auto hs = co_await handshake(timeout);
  if(!hs) co_return tl::unexpected(hs.error());
  while(true) {
    auto rp = co_await conn_.recv(timeout);
    if(!rp) {
      if(rp.error() == make_error_code(errc::connection_closed))
        co_return tl::expected<void, std::error_code>{};
      co_return tl::unexpected(rp.error());
    }
    auto hr = co_await handle(*rp);
    if(!hr) co_return tl::unexpected(hr.error());
  }
}

} // namespace ed2k::share
