#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <tl/expected.hpp>

#include "ed2k/core/hash.hpp"
#include "ed2k/crypto/rc4.hpp"
#include "ed2k/net/packet.hpp"

namespace ed2k::net {

struct TcpObfuscationOptions {
  std::optional<std::byte> marker;
  std::optional<std::uint32_t> random_key_part;
  bool random_padding = true;
  std::vector<std::byte> padding;
};

class EncryptedStreamSocket {
 public:
  explicit EncryptedStreamSocket(boost::asio::any_io_executor ex);
  explicit EncryptedStreamSocket(boost::asio::ip::tcp::socket&& socket);

  EncryptedStreamSocket(EncryptedStreamSocket&&) noexcept = default;
  EncryptedStreamSocket& operator=(EncryptedStreamSocket&&) noexcept = default;

  boost::asio::awaitable<tl::expected<void, std::error_code>>
    connect(IPv4 ip, std::uint16_t port, std::chrono::milliseconds timeout);

  boost::asio::awaitable<tl::expected<void, std::error_code>>
    handshake_initiator(const UserHash& target_hash, std::chrono::milliseconds timeout,
                        const TcpObfuscationOptions& options = {});

  boost::asio::awaitable<tl::expected<void, std::error_code>>
    handshake_acceptor(const UserHash& local_hash, std::chrono::milliseconds timeout,
                       const TcpObfuscationOptions& options = {});

  boost::asio::awaitable<tl::expected<void, std::error_code>> send(const Packet& packet);
  boost::asio::awaitable<tl::expected<Packet, std::error_code>> recv(std::chrono::milliseconds timeout);

  boost::asio::any_io_executor executor() { return socket_.get_executor(); }
  void close() noexcept;
  bool is_open() const noexcept;
  bool encrypted() const noexcept { return encrypted_; }

 private:
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    read_exact(std::span<std::byte> out, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    write_all(std::span<const std::byte> data);
  boost::asio::awaitable<tl::expected<std::vector<std::byte>, std::error_code>>
    read_decrypted(std::size_t size, std::chrono::milliseconds timeout, crypto::RC4& rc4);

  boost::asio::ip::tcp::socket socket_;
  std::optional<crypto::RC4> send_rc4_;
  std::optional<crypto::RC4> receive_rc4_;
  bool encrypted_ = false;
};

} // namespace ed2k::net
