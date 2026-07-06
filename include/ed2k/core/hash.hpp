#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <functional>
#include <tl/expected.hpp>
#include "ed2k/util/error.hpp"
namespace ed2k {
class MD4Hash {
  std::array<std::byte,16> b_{};
 public:
  MD4Hash() = default;
  [[nodiscard]] static constexpr MD4Hash from_bytes(std::array<std::byte,16> b) noexcept { MD4Hash h; h.b_=b; return h; }
  [[nodiscard]] static tl::expected<MD4Hash,std::error_code> from_hex(std::string_view);
  [[nodiscard]] std::string to_hex() const;
  [[nodiscard]] constexpr const std::array<std::byte,16>& bytes() const noexcept { return b_; }
  auto operator<=>(const MD4Hash&) const = default;
};
using FileHash = MD4Hash; using UserHash = MD4Hash; using PartHash = MD4Hash;

class AICHHash {
  std::array<std::byte,20> b_{};
 public:
  AICHHash() = default;
  [[nodiscard]] static constexpr AICHHash from_bytes(std::array<std::byte,20> b) noexcept { AICHHash h; h.b_=b; return h; }
  [[nodiscard]] static tl::expected<AICHHash,std::error_code> from_base32(std::string_view);
  [[nodiscard]] std::string to_base32() const;
  [[nodiscard]] constexpr const std::array<std::byte,20>& bytes() const noexcept { return b_; }
  auto operator<=>(const AICHHash&) const = default;
};

struct IPv4 {
 private:
  std::uint32_t value_ = 0; // 主机序（a 在高位，a<<24|b<<16|c<<8|d，与 asio::address_v4 一致）
 public:
  [[nodiscard]] static constexpr IPv4 from_host(std::uint32_t v) noexcept { IPv4 ip; ip.value_ = v; return ip; }
  [[nodiscard]] constexpr std::uint32_t host() const noexcept { return value_; }
  [[nodiscard]] static tl::expected<IPv4,std::error_code> from_dotted(std::string_view);
  [[nodiscard]] static constexpr IPv4 from_wire(std::uint32_t le) noexcept {
    // Wire u32 has a in the low byte (aMule ReadUInt32 LE); host() keeps a in the high byte.
    return IPv4::from_host(((le&0xFFu)<<24)|((le&0xFF00u)<<8)|((le&0xFF0000u)>>8)|((le&0xFF000000u)>>24));
  }
  [[nodiscard]] std::string to_dotted() const;
  auto operator<=>(const IPv4&) const = default;
};
}
template<> struct std::hash<ed2k::MD4Hash> {
  std::size_t operator()(const ed2k::MD4Hash& h) const noexcept {
    std::uint64_t s = 14695981039346656037ull;
    for(auto b : h.bytes()) {
      s ^= std::to_integer<std::uint8_t>(b);
      s *= 1099511628211ull;
    }
    if constexpr(sizeof(std::size_t) < sizeof(std::uint64_t)) {
      return static_cast<std::size_t>(s ^ (s >> 32));
    } else {
      return static_cast<std::size_t>(s);
    }
  }
};
