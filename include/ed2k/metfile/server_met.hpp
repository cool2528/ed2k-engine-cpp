#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/codec/tag.hpp"
#include "ed2k/util/error.hpp"
namespace ed2k {
namespace stag { constexpr std::uint8_t Name=0x01, Description=0x0B, MaxUsers=0x87, SoftFiles=0x88, HardFiles=0x89; }
struct ServerEntry {
  IPv4 ip; std::uint16_t port=0;
  std::string name, description;
  std::uint32_t users=0, files=0, max_users=0;
  std::vector<codec::Tag> extra;
  auto operator<=>(const ServerEntry&) const = default;
};
struct ServerList { std::vector<ServerEntry> servers; };
tl::expected<ServerList,std::error_code> parse_server_met(std::span<const std::byte>);
std::vector<std::byte> write_server_met(const ServerList&);
}
