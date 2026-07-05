#include "ed2k/net/udp_obfuscation.hpp"

#include <array>
#include <random>

#include "ed2k/crypto/md5.hpp"
#include "ed2k/crypto/rc4.hpp"
#include "ed2k/net/packet.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::net {
namespace {
constexpr std::uint8_t k_magic_client_server = 0x6b;
constexpr std::uint8_t k_magic_server_client = 0xa5;
constexpr std::uint32_t k_magic_udp_sync_server = 0x13ef24d5u;
constexpr std::size_t k_header_without_padding = 8;

bool is_clear_udp_protocol(std::byte value) noexcept {
  const auto protocol = std::to_integer<std::uint8_t>(value);
  return protocol == proto::eDonkey || protocol == proto::zlib ||
         protocol == proto::eMule || protocol == 0xa3 ||
         protocol == 0xb2 || protocol == 0xe4 || protocol == 0xe5;
}

std::uint16_t random_u16() {
  static thread_local std::mt19937 rng{std::random_device{}()};
  return static_cast<std::uint16_t>(std::uniform_int_distribution<unsigned>(1, 0xffff)(rng));
}

std::uint8_t random_marker() {
  static thread_local std::mt19937 rng{std::random_device{}()};
  for (int i = 0; i < 128; ++i) {
    const auto marker = static_cast<std::uint8_t>(std::uniform_int_distribution<unsigned>(0, 0xff)(rng));
    if (!is_clear_udp_protocol(std::byte{marker})) {
      return marker;
    }
  }
  return 0x01;
}

std::uint8_t normalized_marker(std::uint8_t marker) {
  if (marker == 0) {
    return random_marker();
  }
  return is_clear_udp_protocol(std::byte{marker}) ? 0x01 : marker;
}

void append_u16_le(std::vector<std::byte>& out, std::uint16_t value) {
  out.push_back(std::byte(value & 0xffu));
  out.push_back(std::byte((value >> 8) & 0xffu));
}

void append_u32_le(std::vector<std::byte>& out, std::uint32_t value) {
  out.push_back(std::byte(value & 0xffu));
  out.push_back(std::byte((value >> 8) & 0xffu));
  out.push_back(std::byte((value >> 16) & 0xffu));
  out.push_back(std::byte((value >> 24) & 0xffu));
}

void write_u32_le(std::array<std::byte, 4>& out, std::uint32_t value) {
  out[0] = std::byte(value & 0xffu);
  out[1] = std::byte((value >> 8) & 0xffu);
  out[2] = std::byte((value >> 16) & 0xffu);
  out[3] = std::byte((value >> 24) & 0xffu);
}

std::uint32_t read_u32_le(const std::byte* data) noexcept {
  return std::to_integer<std::uint32_t>(data[0]) |
         (std::to_integer<std::uint32_t>(data[1]) << 8) |
         (std::to_integer<std::uint32_t>(data[2]) << 16) |
         (std::to_integer<std::uint32_t>(data[3]) << 24);
}

std::uint8_t key_magic(ServerUdpObfuscationDirection direction) noexcept {
  return direction == ServerUdpObfuscationDirection::client_to_server
             ? k_magic_client_server
             : k_magic_server_client;
}

std::array<std::byte, 16> server_udp_key(std::uint32_t base_key,
                                         ServerUdpObfuscationDirection direction,
                                         std::uint16_t random_key_part) {
  std::vector<std::byte> key_data;
  key_data.reserve(7);
  append_u32_le(key_data, base_key);
  key_data.push_back(std::byte{key_magic(direction)});
  append_u16_le(key_data, random_key_part);
  return crypto::md5(key_data);
}

void rc4_append(crypto::RC4& rc4, std::span<const std::byte> input, std::vector<std::byte>& output) {
  if (input.empty()) {
    return;
  }
  const auto offset = output.size();
  output.insert(output.end(), input.begin(), input.end());
  rc4.process(std::span<std::byte>(output.data() + offset, input.size()));
}

std::vector<std::byte> rc4_process(crypto::RC4& rc4, std::span<const std::byte> input) {
  std::vector<std::byte> output(input.begin(), input.end());
  rc4.process(output);
  return output;
}

ServerUdpObfuscationDecodeResult plain_result(std::span<const std::byte> datagram) {
  ServerUdpObfuscationDecodeResult result;
  result.datagram.assign(datagram.begin(), datagram.end());
  return result;
}
} // namespace

tl::expected<std::vector<std::byte>, std::error_code>
encode_server_udp_obfuscated_datagram(std::span<const std::byte> clear_datagram,
                                      const ServerUdpObfuscationOptions& options) {
  if (options.base_key == 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  const auto random_key_part = options.random_key_part == 0 ? random_u16() : options.random_key_part;
  crypto::RC4 rc4(server_udp_key(options.base_key, options.direction, random_key_part));

  std::vector<std::byte> encoded;
  encoded.reserve(clear_datagram.size() + k_header_without_padding);
  encoded.push_back(std::byte{normalized_marker(options.marker)});
  append_u16_le(encoded, random_key_part);

  std::array<std::byte, 4> magic{};
  write_u32_le(magic, k_magic_udp_sync_server);
  rc4_append(rc4, magic, encoded);
  encoded.push_back(rc4.process_byte(std::byte{0x00}));
  rc4_append(rc4, clear_datagram, encoded);
  return encoded;
}

tl::expected<ServerUdpObfuscationDecodeResult, std::error_code>
decode_server_udp_obfuscated_datagram(std::span<const std::byte> datagram,
                                      const ServerUdpObfuscationDecodeOptions& options) {
  if (options.base_key == 0 || datagram.size() <= k_header_without_padding ||
      is_clear_udp_protocol(datagram[0])) {
    return plain_result(datagram);
  }

  const auto random_key_part = static_cast<std::uint16_t>(
      std::to_integer<std::uint16_t>(datagram[1]) |
      (std::to_integer<std::uint16_t>(datagram[2]) << 8));
  crypto::RC4 rc4(server_udp_key(options.base_key, options.direction, random_key_part));

  const auto magic = rc4_process(rc4, datagram.subspan(3, 4));
  if (magic.size() != 4 || read_u32_le(magic.data()) != k_magic_udp_sync_server) {
    return plain_result(datagram);
  }

  const auto pad_len = std::to_integer<std::uint8_t>(rc4.process_byte(datagram[7])) & 0x0fu;
  const auto encrypted_remaining = datagram.size() - k_header_without_padding;
  if (encrypted_remaining <= static_cast<std::size_t>(pad_len)) {
    return plain_result(datagram);
  }
  rc4.discard(pad_len);

  ServerUdpObfuscationDecodeResult result;
  result.datagram = rc4_process(rc4, datagram.subspan(k_header_without_padding + pad_len));
  result.encrypted = true;
  return result;
}

} // namespace ed2k::net

