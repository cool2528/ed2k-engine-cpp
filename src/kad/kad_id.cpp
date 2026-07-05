#include "ed2k/kad/kad_id.hpp"

#include <array>
#include <cstddef>

#include "crypto/md4.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::kad {
namespace {
int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
} // namespace

tl::expected<KadID, std::error_code> KadID::from_hex(std::string_view hex) {
  if (hex.size() != size * 2) {
    return tl::unexpected(make_error_code(errc::invalid_hex));
  }

  std::array<std::byte, size> out{};
  for (std::size_t i = 0; i < size; ++i) {
    const int hi = hex_value(hex[i * 2]);
    const int lo = hex_value(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return tl::unexpected(make_error_code(errc::invalid_hex));
    }
    out[i] = std::byte((hi << 4) | lo);
  }
  return KadID::from_bytes(out);
}

KadID KadID::from_user_hash(const UserHash& user_hash, std::uint32_t nonce) noexcept {
  std::array<std::byte, 20> seed{};
  for (std::size_t i = 0; i < user_hash.bytes().size(); ++i) {
    seed[i] = user_hash.bytes()[i];
  }
  seed[16] = std::byte(nonce & 0xffu);
  seed[17] = std::byte((nonce >> 8) & 0xffu);
  seed[18] = std::byte((nonce >> 16) & 0xffu);
  seed[19] = std::byte((nonce >> 24) & 0xffu);
  return KadID::from_bytes(crypto::md4(seed));
}

std::string KadID::to_hex() const {
  static constexpr char k_digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (auto b : bytes_) {
    const auto value = std::to_integer<unsigned>(b);
    out += k_digits[value >> 4];
    out += k_digits[value & 0x0f];
  }
  return out;
}

std::uint8_t KadID::bit(std::size_t index) const noexcept {
  if (index >= size * 8) {
    return 0;
  }
  const auto value = std::to_integer<std::uint8_t>(bytes_[index / 8]);
  const auto shift = static_cast<unsigned>(7 - (index % 8));
  return static_cast<std::uint8_t>((value >> shift) & 0x01u);
}

KadID xor_distance(const KadID& lhs, const KadID& rhs) noexcept {
  std::array<std::byte, KadID::size> out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = std::byte(std::to_integer<unsigned>(lhs.bytes()[i]) ^
                       std::to_integer<unsigned>(rhs.bytes()[i]));
  }
  return KadID::from_bytes(out);
}

bool closer_to_target(const KadID& lhs, const KadID& rhs, const KadID& target) noexcept {
  return xor_distance(lhs, target) < xor_distance(rhs, target);
}

std::array<std::byte, KadID::size> kad_id_to_uint128_wire(const KadID& id) noexcept {
  std::array<std::byte, KadID::size> out{};
  const auto& bytes = id.bytes();
  for (std::size_t chunk = 0; chunk < 4; ++chunk) {
    const auto base = chunk * 4;
    out[base + 0] = bytes[base + 3];
    out[base + 1] = bytes[base + 2];
    out[base + 2] = bytes[base + 1];
    out[base + 3] = bytes[base + 0];
  }
  return out;
}

KadID kad_id_from_uint128_wire(std::span<const std::byte, KadID::size> wire) noexcept {
  std::array<std::byte, KadID::size> out{};
  for (std::size_t chunk = 0; chunk < 4; ++chunk) {
    const auto base = chunk * 4;
    out[base + 0] = wire[base + 3];
    out[base + 1] = wire[base + 2];
    out[base + 2] = wire[base + 1];
    out[base + 3] = wire[base + 0];
  }
  return KadID::from_bytes(out);
}

} // namespace ed2k::kad
