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
  static MD4Hash from_bytes(std::array<std::byte,16> b){ MD4Hash h; h.b_=b; return h; }
  static tl::expected<MD4Hash,std::error_code> from_hex(std::string_view);
  std::string to_hex() const;
  const std::array<std::byte,16>& bytes() const { return b_; }
  auto operator<=>(const MD4Hash&) const = default;
};
using FileHash = MD4Hash; using UserHash = MD4Hash; using PartHash = MD4Hash;

class AICHHash {
  std::array<std::byte,20> b_{};
 public:
  AICHHash() = default;
  static AICHHash from_bytes(std::array<std::byte,20> b){ AICHHash h; h.b_=b; return h; }
  static tl::expected<AICHHash,std::error_code> from_base32(std::string_view);
  std::string to_base32() const;
  const std::array<std::byte,20>& bytes() const { return b_; }
  auto operator<=>(const AICHHash&) const = default;
};

struct IPv4 {
 private:
  std::uint32_t value_ = 0; // 主机序（a 在高位，a<<24|b<<16|c<<8|d，与 asio::address_v4 一致）
 public:
  static constexpr IPv4 from_host(std::uint32_t v) noexcept { IPv4 ip; ip.value_ = v; return ip; }
  constexpr std::uint32_t host() const noexcept { return value_; }
  static tl::expected<IPv4,std::error_code> from_dotted(std::string_view);
  static IPv4 from_wire(std::uint32_t le); // 线序 u32（a 在低位，aMule ReadUInt32）→ IPv4
  std::string to_dotted() const;
  auto operator<=>(const IPv4&) const = default;
};
}
template<> struct std::hash<ed2k::MD4Hash> {
  std::size_t operator()(const ed2k::MD4Hash& h) const noexcept {
    std::size_t s=0; for(auto b:h.bytes()) s=s*131+std::to_integer<unsigned>(b); return s;
  }
};
