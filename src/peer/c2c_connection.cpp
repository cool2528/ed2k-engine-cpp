#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/util/error.hpp"
#include <chrono>
namespace ed2k::peer {
namespace asio = boost::asio;
using clock_type = std::chrono::steady_clock;

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
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::HELLO; req.payload=encode_hello(mine);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::HELLOANSWER, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_hello_answer(rp->payload);
}
asio::awaitable<tl::expected<HelloInfo,std::error_code>>
C2CConnection::handshake_acceptor(const HelloInfo& mine, std::chrono::milliseconds timeout){
  // acceptor: peer (TCP initiator) sends HELLO first; we decode it then reply HELLOANSWER.
  // HELLO 与 HELLOANSWER 线格式相同(aMule ProcessHelloPacket 同一例程处理二者),
  // 故复用 decode_hello_answer 解码对端 HELLO、encode_hello 编码我方 HELLOANSWER。
  auto rp = co_await pump_until(op::HELLO, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  auto peer = decode_hello_answer(rp->payload);
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
  co_return decode_hashset_answer(rp->payload);
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
  auto deadline = clock_type::now() + timeout;
  std::vector<Block> blocks;
  while(blocks.size() < 3){
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if(rem.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto rp = co_await conn_.recv(rem);
    if(!rp) co_return tl::unexpected(rp.error());
    auto& pkt = *rp;
    if(pkt.opcode == op::SENDINGPART){ auto b=decode_sending_part(pkt.payload); if(!b) co_return tl::unexpected(b.error()); blocks.push_back(std::move(*b)); }
    else if(pkt.opcode == op::COMPRESSEDPART){ auto b=decode_compressed_part(pkt.payload); if(!b) co_return tl::unexpected(b.error()); blocks.push_back(std::move(*b)); }
    else if(pkt.opcode == op::OUTOFPARTREQS){ break; }
    else if(pkt.opcode == op::FILEREQANSNOFIL){ co_return tl::unexpected(make_error_code(errc::file_not_found)); }
    else continue;
  }
  co_return blocks;
}

asio::awaitable<tl::expected<std::vector<Block>,std::error_code>>
C2CConnection::request_blocks_i64(const FileHash& h, std::array<std::uint64_t,3> starts, std::array<std::uint64_t,3> ends, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::REQUESTPARTS_I64; req.payload=encode_request_parts_i64(h, starts, ends);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto deadline = std::chrono::steady_clock::now() + timeout;
  std::vector<Block> blocks;
  while(blocks.size() < 3){
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if(rem.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto rp = co_await conn_.recv(rem);
    if(!rp) co_return tl::unexpected(rp.error());
    auto& pkt = *rp;
    if(pkt.opcode == op::SENDINGPART_I64){ auto b=decode_sending_part_i64(pkt.payload); if(!b) co_return tl::unexpected(b.error()); blocks.push_back(std::move(*b)); }
    else if(pkt.opcode == op::COMPRESSEDPART_I64){ auto b=decode_compressed_part_i64(pkt.payload); if(!b) co_return tl::unexpected(b.error()); blocks.push_back(std::move(*b)); }
    else if(pkt.opcode == op::OUTOFPARTREQS){ break; }
    else if(pkt.opcode == op::FILEREQANSNOFIL){ co_return tl::unexpected(make_error_code(errc::file_not_found)); }
    else continue;
  }
  co_return blocks;
}

asio::awaitable<tl::expected<std::vector<std::array<std::byte,20>>,std::error_code>>
C2CConnection::request_aich_proof(const FileHash& h, std::uint16_t block_index, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=op::AICHREQUEST;
  req.payload=encode_aich_request(h, block_index);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::AICHANSWER, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_aich_answer(rp->payload);
}
}
