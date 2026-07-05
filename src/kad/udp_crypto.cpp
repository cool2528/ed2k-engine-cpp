#include "ed2k/kad/udp_crypto.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <random>

#include "ed2k/crypto/md5.hpp"
#include "ed2k/kad/messages.hpp"
#include "ed2k/net/packet.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::kad {
namespace {
constexpr std::uint32_t k_magic_udp_sync_client = 0x395f2ec1u;
constexpr std::size_t k_header_without_padding = 8;
constexpr std::size_t k_kad_verify_keys_size = 8;

bool is_clear_udp_protocol(std::byte value) noexcept {
  const auto protocol = std::to_integer<std::uint8_t>(value);
  return protocol == net::proto::eDonkey || protocol == net::proto::eMule ||
         protocol == net::proto::zlib || protocol == kad_protocol;
}

std::uint16_t random_u16() {
  static thread_local std::mt19937 rng{std::random_device{}()};
  return static_cast<std::uint16_t>(std::uniform_int_distribution<unsigned>(1, 0xffff)(rng));
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

std::array<std::byte, 16> key_by_target_id(const KadID& target_id, std::uint16_t random_key_part) {
  const auto crypt_id = kad_id_crypt_bytes(target_id);
  std::vector<std::byte> key_data(crypt_id.begin(), crypt_id.end());
  append_u16_le(key_data, random_key_part);
  return crypto::md5(key_data);
}

std::array<std::byte, 16> key_by_receiver_verify(std::uint32_t receiver_verify_key,
                                                  std::uint16_t random_key_part) {
  std::vector<std::byte> key_data;
  key_data.reserve(6);
  append_u32_le(key_data, receiver_verify_key);
  append_u16_le(key_data, random_key_part);
  return crypto::md5(key_data);
}

class Rc4 {
 public:
  explicit Rc4(std::span<const std::byte, 16> key) {
    for (std::size_t n = 0; n < state_.size(); ++n) {
      state_[n] = static_cast<std::uint8_t>(n);
    }

    std::uint8_t j = 0;
    for (std::size_t n = 0; n < state_.size(); ++n) {
      j = static_cast<std::uint8_t>(j + state_[n] + std::to_integer<std::uint8_t>(key[n % key.size()]));
      std::swap(state_[n], state_[j]);
    }
  }

  void crypt(std::span<const std::byte> input, std::vector<std::byte>& output) {
    output.reserve(output.size() + input.size());
    for (auto value : input) {
      output.push_back(std::byte(std::to_integer<std::uint8_t>(value) ^ next()));
    }
  }

  std::vector<std::byte> crypt(std::span<const std::byte> input) {
    std::vector<std::byte> output;
    crypt(input, output);
    return output;
  }

  std::byte crypt_byte(std::byte value) {
    return std::byte(std::to_integer<std::uint8_t>(value) ^ next());
  }

  void discard(std::size_t count) {
    for (std::size_t n = 0; n < count; ++n) {
      (void)next();
    }
  }

 private:
  std::uint8_t next() {
    i_ = static_cast<std::uint8_t>(i_ + 1u);
    j_ = static_cast<std::uint8_t>(j_ + state_[i_]);
    std::swap(state_[i_], state_[j_]);
    return state_[static_cast<std::uint8_t>(state_[i_] + state_[j_])];
  }

  std::array<std::uint8_t, 256> state_{};
  std::uint8_t i_ = 0;
  std::uint8_t j_ = 0;
};

std::uint8_t normalized_marker(const KadUdpEncryptOptions& options) noexcept {
  const bool receiver_key_mode = !options.target_id.has_value();
  auto marker = options.marker;
  if (receiver_key_mode) {
    marker = static_cast<std::uint8_t>((marker & 0xfcu) | 0x02u);
  } else {
    marker = static_cast<std::uint8_t>(marker & 0xfcu);
  }
  if (is_clear_udp_protocol(std::byte{marker})) {
    marker = receiver_key_mode ? 0x02 : 0x00;
  }
  return marker;
}
} // namespace

std::uint32_t kad_udp_verify_key(std::uint32_t kad_udp_key, IPv4 target_ip) {
  std::vector<std::byte> input;
  input.reserve(8);
  append_u32_le(input, target_ip.host());
  append_u32_le(input, kad_udp_key);
  const auto digest = crypto::md5(input);
  const auto mixed = read_u32_le(digest.data()) ^
                     read_u32_le(digest.data() + 4) ^
                     read_u32_le(digest.data() + 8) ^
                     read_u32_le(digest.data() + 12);
  return (mixed % 0xfffffffEu) + 1u;
}

std::array<std::byte, 16> kad_id_crypt_bytes(const KadID& id) noexcept {
  return kad_id_to_uint128_wire(id);
}

tl::expected<std::vector<std::byte>, std::error_code>
encode_kad_obfuscated_datagram(std::span<const std::byte> clear_datagram,
                                const KadUdpEncryptOptions& options) {
  const bool receiver_key_mode = !options.target_id.has_value();
  if (receiver_key_mode && options.receiver_verify_key == 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  const auto random_key_part = options.random_key_part == 0 ? random_u16() : options.random_key_part;
  const auto key = receiver_key_mode ? key_by_receiver_verify(options.receiver_verify_key, random_key_part)
                                     : key_by_target_id(*options.target_id, random_key_part);
  Rc4 rc4(key);

  std::vector<std::byte> encoded;
  encoded.reserve(clear_datagram.size() + k_header_without_padding + k_kad_verify_keys_size);
  encoded.push_back(std::byte{normalized_marker(options)});
  append_u16_le(encoded, random_key_part);

  std::array<std::byte, 4> magic{};
  write_u32_le(magic, k_magic_udp_sync_client);
  rc4.crypt(magic, encoded);

  encoded.push_back(rc4.crypt_byte(std::byte{0x00}));

  std::array<std::byte, 4> verify{};
  write_u32_le(verify, options.receiver_verify_key);
  rc4.crypt(verify, encoded);
  write_u32_le(verify, options.sender_verify_key);
  rc4.crypt(verify, encoded);

  rc4.crypt(clear_datagram, encoded);
  return encoded;
}

tl::expected<KadUdpDecodeResult, std::error_code>
decode_kad_obfuscated_datagram(std::span<const std::byte> datagram,
                                const KadID& local_id,
                                std::uint32_t local_receiver_verify_key) {
  if (datagram.size() <= k_header_without_padding || is_clear_udp_protocol(datagram[0])) {
    KadUdpDecodeResult result;
    result.datagram.assign(datagram.begin(), datagram.end());
    return result;
  }

  const auto random_key_part = static_cast<std::uint16_t>(
      std::to_integer<std::uint16_t>(datagram[1]) |
      (std::to_integer<std::uint16_t>(datagram[2]) << 8));
  std::uint8_t current_try = (std::to_integer<std::uint8_t>(datagram[0]) & 0x03u) == 3u
                                 ? 1u
                                 : static_cast<std::uint8_t>(std::to_integer<std::uint8_t>(datagram[0]) & 0x03u);

  for (int attempt = 0; attempt < 3; ++attempt) {
    std::optional<std::array<std::byte, 16>> key;
    if (current_try == 0) {
      key = key_by_target_id(local_id, random_key_part);
    } else if (current_try == 2 && local_receiver_verify_key != 0) {
      key = key_by_receiver_verify(local_receiver_verify_key, random_key_part);
    }
    current_try = static_cast<std::uint8_t>((current_try + 1u) % 3u);
    if (!key) {
      continue;
    }

    Rc4 rc4(*key);
    const auto magic = rc4.crypt(datagram.subspan(3, 4));
    if (magic.size() != 4 ||
        read_u32_le(magic.data()) != k_magic_udp_sync_client) {
      continue;
    }

    const auto pad_len = std::to_integer<std::uint8_t>(rc4.crypt_byte(datagram[7]));
    const auto encrypted_remaining = datagram.size() - k_header_without_padding;
    if (encrypted_remaining <= static_cast<std::size_t>(pad_len) + k_kad_verify_keys_size) {
      KadUdpDecodeResult result;
      result.datagram.assign(datagram.begin(), datagram.end());
      return result;
    }
    rc4.discard(pad_len);

    auto receiver_key_bytes = rc4.crypt(datagram.subspan(k_header_without_padding + pad_len, 4));
    auto sender_key_bytes = rc4.crypt(datagram.subspan(k_header_without_padding + pad_len + 4, 4));
    const auto receiver_key = read_u32_le(receiver_key_bytes.data());
    const auto sender_key = read_u32_le(sender_key_bytes.data());

    const auto payload_offset = k_header_without_padding + pad_len + k_kad_verify_keys_size;
    auto payload = rc4.crypt(datagram.subspan(payload_offset));

    KadUdpDecodeResult result;
    result.datagram = std::move(payload);
    result.receiver_verify_key = receiver_key;
    result.sender_verify_key = sender_key;
    result.encrypted = true;
    result.valid_receiver_key = receiver_key != 0 && receiver_key == local_receiver_verify_key;
    return result;
  }

  KadUdpDecodeResult result;
  result.datagram.assign(datagram.begin(), datagram.end());
  return result;
}

} // namespace ed2k::kad
