#include "ed2k/net/encrypted_stream_socket.hpp"

#include <algorithm>
#include <array>
#include <random>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include "ed2k/crypto/md5.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::net {
namespace {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

constexpr std::uint8_t k_magic_requester = 34;
constexpr std::uint8_t k_magic_server = 203;
constexpr std::uint32_t k_magic_sync = 0x835e6fc4u;
constexpr std::uint8_t k_method_obfuscation = 0x00;
constexpr std::size_t k_rc4_discard = 1024;
constexpr std::uint8_t k_default_max_padding = 16;

bool is_plain_protocol_marker(std::byte value) noexcept {
  const auto marker = std::to_integer<std::uint8_t>(value);
  return marker == proto::eDonkey || marker == proto::zlib || marker == proto::eMule;
}

std::mt19937& rng() {
  static thread_local std::mt19937 engine{std::random_device{}()};
  return engine;
}

std::uint8_t random_u8() {
  return static_cast<std::uint8_t>(std::uniform_int_distribution<unsigned>(0, 0xff)(rng()));
}

std::uint32_t random_u32() {
  return std::uniform_int_distribution<std::uint32_t>()(rng());
}

std::byte random_marker() {
  for (int attempt = 0; attempt < 128; ++attempt) {
    const auto marker = std::byte{random_u8()};
    if (!is_plain_protocol_marker(marker)) {
      return marker;
    }
  }
  return std::byte{0x01};
}

std::vector<std::byte> padding_for(const TcpObfuscationOptions& options) {
  if (!options.random_padding) {
    return options.padding;
  }

  const auto len = std::uniform_int_distribution<unsigned>(0, k_default_max_padding)(rng());
  std::vector<std::byte> padding;
  padding.reserve(len);
  for (unsigned i = 0; i < len; ++i) {
    padding.push_back(std::byte{random_u8()});
  }
  return padding;
}

void append_u32_le(std::vector<std::byte>& out, std::uint32_t value) {
  out.push_back(std::byte(value & 0xffu));
  out.push_back(std::byte((value >> 8) & 0xffu));
  out.push_back(std::byte((value >> 16) & 0xffu));
  out.push_back(std::byte((value >> 24) & 0xffu));
}

std::uint32_t read_u32_le(std::span<const std::byte> data) noexcept {
  return std::to_integer<std::uint32_t>(data[0]) |
         (std::to_integer<std::uint32_t>(data[1]) << 8) |
         (std::to_integer<std::uint32_t>(data[2]) << 16) |
         (std::to_integer<std::uint32_t>(data[3]) << 24);
}

crypto::RC4 make_tcp_rc4(const UserHash& hash, std::uint8_t role_magic, std::uint32_t random_key_part) {
  std::array<std::byte, 21> key_data{};
  std::copy(hash.bytes().begin(), hash.bytes().end(), key_data.begin());
  key_data[16] = std::byte{role_magic};
  key_data[17] = std::byte(random_key_part & 0xffu);
  key_data[18] = std::byte((random_key_part >> 8) & 0xffu);
  key_data[19] = std::byte((random_key_part >> 16) & 0xffu);
  key_data[20] = std::byte((random_key_part >> 24) & 0xffu);

  crypto::RC4 rc4(crypto::md5(key_data));
  rc4.discard(k_rc4_discard);
  return rc4;
}
} // namespace

EncryptedStreamSocket::EncryptedStreamSocket(asio::any_io_executor ex) : socket_(ex) {}

EncryptedStreamSocket::EncryptedStreamSocket(tcp::socket&& socket) : socket_(std::move(socket)) {
  boost::system::error_code ignored;
  socket_.set_option(tcp::no_delay(true), ignored);
}

void EncryptedStreamSocket::close() noexcept {
  boost::system::error_code ignored;
  socket_.cancel(ignored);
  socket_.close(ignored);
}

bool EncryptedStreamSocket::is_open() const noexcept {
  return socket_.is_open();
}

asio::awaitable<tl::expected<void, std::error_code>>
EncryptedStreamSocket::connect(IPv4 ip, std::uint16_t port, std::chrono::milliseconds timeout) {
  tcp::endpoint endpoint(asio::ip::address_v4(ip.host()), port);
  auto [ec] = co_await socket_.async_connect(
      endpoint, asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  if (ec) {
    if (ec == asio::error::operation_aborted) {
      co_return tl::unexpected(make_error_code(errc::timed_out));
    }
    co_return tl::unexpected(make_error_code(errc::connect_failed));
  }

  boost::system::error_code ignored;
  socket_.set_option(tcp::no_delay(true), ignored);
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
EncryptedStreamSocket::read_exact(std::span<std::byte> out, std::chrono::milliseconds timeout) {
  if (out.empty()) {
    co_return tl::expected<void, std::error_code>{};
  }

  auto [ec, n] = co_await asio::async_read(
      socket_, asio::buffer(out.data(), out.size()),
      asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  (void)n;
  if (ec) {
    if (ec == asio::error::operation_aborted) {
      co_return tl::unexpected(make_error_code(errc::timed_out));
    }
    co_return tl::unexpected(make_error_code(errc::connection_closed));
  }
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
EncryptedStreamSocket::write_all(std::span<const std::byte> data) {
  if (data.empty()) {
    co_return tl::expected<void, std::error_code>{};
  }

  auto [ec, n] = co_await asio::async_write(
      socket_, asio::buffer(data.data(), data.size()), asio::as_tuple(asio::use_awaitable));
  (void)n;
  if (ec) {
    co_return tl::unexpected(make_error_code(errc::connection_closed));
  }
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<std::vector<std::byte>, std::error_code>>
EncryptedStreamSocket::read_decrypted(std::size_t size, std::chrono::milliseconds timeout, crypto::RC4& rc4) {
  std::vector<std::byte> data(size);
  auto read = co_await read_exact(data, timeout);
  if (!read) {
    co_return tl::unexpected(read.error());
  }
  rc4.process(data);
  co_return data;
}

asio::awaitable<tl::expected<void, std::error_code>>
EncryptedStreamSocket::handshake_initiator(const UserHash& target_hash, std::chrono::milliseconds timeout,
                                           const TcpObfuscationOptions& options) {
  const auto random_key_part = options.random_key_part.value_or(random_u32());
  send_rc4_.emplace(make_tcp_rc4(target_hash, k_magic_requester, random_key_part));
  receive_rc4_.emplace(make_tcp_rc4(target_hash, k_magic_server, random_key_part));

  const auto padding = padding_for(options);
  if (padding.size() > 255) {
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  std::vector<std::byte> request;
  request.reserve(12 + padding.size());
  request.push_back(options.marker.value_or(random_marker()));
  append_u32_le(request, random_key_part);
  append_u32_le(request, k_magic_sync);
  request.push_back(std::byte{k_method_obfuscation});
  request.push_back(std::byte{k_method_obfuscation});
  request.push_back(std::byte(padding.size()));
  request.insert(request.end(), padding.begin(), padding.end());
  send_rc4_->process(std::span<std::byte>(request.data() + 5, request.size() - 5));

  auto written = co_await write_all(request);
  if (!written) {
    co_return tl::unexpected(written.error());
  }

  auto magic = co_await read_decrypted(4, timeout, *receive_rc4_);
  if (!magic) {
    co_return tl::unexpected(magic.error());
  }
  if (read_u32_le(*magic) != k_magic_sync) {
    co_return tl::unexpected(make_error_code(errc::bad_magic));
  }

  auto method_and_padding = co_await read_decrypted(2, timeout, *receive_rc4_);
  if (!method_and_padding) {
    co_return tl::unexpected(method_and_padding.error());
  }
  if ((*method_and_padding)[0] != std::byte{k_method_obfuscation}) {
    co_return tl::unexpected(make_error_code(errc::unsupported_version));
  }
  const auto padding_len = std::to_integer<std::uint8_t>((*method_and_padding)[1]);
  auto ignored_padding = co_await read_decrypted(padding_len, timeout, *receive_rc4_);
  if (!ignored_padding) {
    co_return tl::unexpected(ignored_padding.error());
  }

  encrypted_ = true;
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
EncryptedStreamSocket::handshake_acceptor(const UserHash& local_hash, std::chrono::milliseconds timeout,
                                          const TcpObfuscationOptions& options) {
  std::array<std::byte, 1> marker{};
  auto marker_read = co_await read_exact(marker, timeout);
  if (!marker_read) {
    co_return tl::unexpected(marker_read.error());
  }
  if (is_plain_protocol_marker(marker[0])) {
    co_return tl::unexpected(make_error_code(errc::bad_magic));
  }

  std::array<std::byte, 4> random_bytes{};
  auto random_read = co_await read_exact(random_bytes, timeout);
  if (!random_read) {
    co_return tl::unexpected(random_read.error());
  }
  const auto random_key_part = read_u32_le(random_bytes);

  receive_rc4_.emplace(make_tcp_rc4(local_hash, k_magic_requester, random_key_part));
  send_rc4_.emplace(make_tcp_rc4(local_hash, k_magic_server, random_key_part));

  auto magic = co_await read_decrypted(4, timeout, *receive_rc4_);
  if (!magic) {
    co_return tl::unexpected(magic.error());
  }
  if (read_u32_le(*magic) != k_magic_sync) {
    co_return tl::unexpected(make_error_code(errc::bad_magic));
  }

  auto methods = co_await read_decrypted(3, timeout, *receive_rc4_);
  if (!methods) {
    co_return tl::unexpected(methods.error());
  }
  if ((*methods)[1] != std::byte{k_method_obfuscation}) {
    co_return tl::unexpected(make_error_code(errc::unsupported_version));
  }
  const auto request_padding_len = std::to_integer<std::uint8_t>((*methods)[2]);
  auto ignored_padding = co_await read_decrypted(request_padding_len, timeout, *receive_rc4_);
  if (!ignored_padding) {
    co_return tl::unexpected(ignored_padding.error());
  }

  const auto padding = padding_for(options);
  if (padding.size() > 255) {
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  std::vector<std::byte> response;
  response.reserve(6 + padding.size());
  append_u32_le(response, k_magic_sync);
  response.push_back(std::byte{k_method_obfuscation});
  response.push_back(std::byte(padding.size()));
  response.insert(response.end(), padding.begin(), padding.end());
  send_rc4_->process(response);

  auto written = co_await write_all(response);
  if (!written) {
    co_return tl::unexpected(written.error());
  }

  encrypted_ = true;
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
EncryptedStreamSocket::send(const Packet& packet) {
  auto frame = encode_frame(packet);
  if (encrypted_ && send_rc4_) {
    send_rc4_->process(frame);
  }
  co_return co_await write_all(frame);
}

asio::awaitable<tl::expected<Packet, std::error_code>>
EncryptedStreamSocket::recv(std::chrono::milliseconds timeout) {
  std::array<std::byte, 5> header{};
  auto header_read = co_await read_exact(header, timeout);
  if (!header_read) {
    co_return tl::unexpected(header_read.error());
  }
  if (encrypted_ && receive_rc4_) {
    receive_rc4_->process(header);
  }

  auto parsed_header = parse_header(header);
  if (!parsed_header) {
    co_return tl::unexpected(parsed_header.error());
  }

  std::vector<std::byte> body(parsed_header->size);
  auto body_read = co_await read_exact(body, timeout);
  if (!body_read) {
    co_return tl::unexpected(body_read.error());
  }
  if (encrypted_ && receive_rc4_) {
    receive_rc4_->process(body);
  }

  co_return assemble(parsed_header->protocol, body);
}

} // namespace ed2k::net
