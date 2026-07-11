#pragma once
#include <chrono>
#include <cstdint>
#include <array>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/server/messages.hpp"
namespace ed2k::net { class EncryptedStreamSocket; struct Packet; }
namespace ed2k::share { class UploadSession; }
namespace ed2k::peer {
enum class ObfuscationPolicy { disabled, preferred, required };

struct PeerIdentity {
  server::SourceEndpoint endpoint;
  // Server sources contain only endpoint data; validated Kad sources and Source
  // Exchange v2 callers can preserve their remote user hash here. A missing hash
  // makes preferred mode use plaintext and required mode fail before dialing.
  std::optional<UserHash> user_hash;
};

inline PeerIdentity peer_identity(const PeerSource& source) {
  return PeerIdentity{{source.client_id, source.port}, source.user_hash};
}

struct C2CHandshakeResult {
  HelloInfo hello;
  MuleInfo mule_info;
};

class C2CConnection {
 public:
  explicit C2CConnection(boost::asio::any_io_executor ex);
  explicit C2CConnection(boost::asio::ip::tcp::socket&& s);
  ~C2CConnection();
  C2CConnection(const C2CConnection&) = delete;
  C2CConnection& operator=(const C2CConnection&) = delete;
  C2CConnection(C2CConnection&&) noexcept;
  C2CConnection& operator=(C2CConnection&&) noexcept;

  void set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level = 127);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    connect(IPv4 ip, std::uint16_t port, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    connect(const PeerIdentity& peer, ObfuscationPolicy policy,
            std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<HelloInfo,std::error_code>>
    handshake(const HelloInfo& mine, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<C2CHandshakeResult,std::error_code>>
    handshake_with_mule_info(const HelloInfo& mine, const MuleInfo& mule_info, std::chrono::milliseconds timeout);
  // acceptor 模式握手:对端(TCP 主动方,如 LowID 回调里拨入 InboundListener 的源)
  // 先发 HELLO,我方解码后回 HELLOANSWER。HELLO 与 HELLOANSWER 线格式相同
  // (aMule ProcessHelloPacket 同一例程处理二者),故复用 decode_hello_answer/
  // encode_hello,仅由调用方在 net::Packet 上设置 op::HELLO/op::HELLOANSWER。
  boost::asio::awaitable<tl::expected<HelloInfo,std::error_code>>
    handshake_acceptor(const HelloInfo& mine, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<C2CHandshakeResult,std::error_code>>
    handshake_acceptor_with_mule_info(const HelloInfo& mine, const MuleInfo& mule_info, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<MuleInfo,std::error_code>>
    exchange_mule_info(const MuleInfo& mine, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<FileStatus,std::error_code>>
    request_file(const FileHash&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<PartHash>,std::error_code>>
    request_hashset(const FileHash&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::string,std::error_code>>
    request_filename(const FileHash&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    start_upload(const FileHash&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<Block>,std::error_code>>
    request_blocks(const FileHash&, std::array<std::uint32_t,3> starts, std::array<std::uint32_t,3> ends, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<Block>,std::error_code>>
    request_blocks_i64(const FileHash&, std::array<std::uint64_t,3> starts, std::array<std::uint64_t,3> ends, std::chrono::milliseconds timeout);
  // AICH master hash 交换 (OP_AICHFILEHASHREQ 0x9E -> OP_AICHFILEHASHANS 0x9D, 均 OP_EMULEPROT)
  boost::asio::awaitable<tl::expected<AICHHash,std::error_code>>
    request_aich_master_hash(const FileHash&, std::chrono::milliseconds timeout);
  // SourceExchange v2 (OP_REQUESTSOURCES2 0x83 -> OP_ANSWERSOURCES2 0x84, 均 OP_EMULEPROT)
  boost::asio::awaitable<tl::expected<SourceExchangeAnswer,std::error_code>>
    request_sources2(const FileHash&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    send_file_desc(std::uint8_t rating, std::string_view comment);
  // AICH part 恢复数据 (OP_AICHREQUEST 0x9B -> OP_AICHANSWER 0x9C, 均 OP_EMULEPROT)
  boost::asio::awaitable<tl::expected<AICHRecoveryData,std::error_code>>
    request_aich_proof(const FileHash&, const AICHHash& master, std::uint16_t part_index, std::chrono::milliseconds timeout);
  void close() noexcept;
  bool encrypted() const noexcept;
 private:
  friend class InboundListener;
  friend class ed2k::share::UploadSession;
  C2CConnection(ed2k::net::EncryptedStreamSocket&& stream, std::optional<IPv4> remote);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    send_packet(const ed2k::net::Packet& packet);
  boost::asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
    recv_packet(std::chrono::milliseconds timeout);
  boost::asio::any_io_executor executor();
  std::optional<IPv4> remote_ip() const;
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}
