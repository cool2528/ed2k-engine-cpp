#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <tl/expected.hpp>

#include "ed2k/core/hash.hpp"

namespace ed2k::kad {

class KadID {
  std::array<std::byte, 16> bytes_{};

 public:
  static constexpr std::size_t size = 16;

  KadID() = default;

  static constexpr KadID from_bytes(std::array<std::byte, size> bytes) noexcept {
    KadID id;
    id.bytes_ = bytes;
    return id;
  }

  static tl::expected<KadID, std::error_code> from_hex(std::string_view hex);
  static KadID from_user_hash(const UserHash& user_hash, std::uint32_t nonce) noexcept;

  const std::array<std::byte, size>& bytes() const noexcept { return bytes_; }
  std::string to_hex() const;

  // Bit 0 is the most significant bit, matching aMule CUInt128::GetBitNumber.
  std::uint8_t bit(std::size_t index) const noexcept;

  auto operator<=>(const KadID&) const = default;
};

static_assert(sizeof(KadID) == 16);

KadID xor_distance(const KadID& lhs, const KadID& rhs) noexcept;
bool closer_to_target(const KadID& lhs, const KadID& rhs, const KadID& target) noexcept;
std::array<std::byte, KadID::size> kad_id_to_uint128_wire(const KadID& id) noexcept;
KadID kad_id_from_uint128_wire(std::span<const std::byte, KadID::size> wire) noexcept;

} // namespace ed2k::kad

template <>
struct std::hash<ed2k::kad::KadID> {
  std::size_t operator()(const ed2k::kad::KadID& id) const noexcept {
    std::size_t seed = 0;
    for (auto b : id.bytes()) {
      seed = seed * 131 + std::to_integer<unsigned>(b);
    }
    return seed;
  }
};
