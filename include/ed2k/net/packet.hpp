#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <compare>
namespace ed2k::net {
namespace proto { constexpr std::uint8_t eDonkey = 0xE3, eMule = 0xC5, zlib = 0xD4; }
struct Packet {
  std::uint8_t protocol = proto::eDonkey;
  std::uint8_t opcode = 0;
  std::vector<std::byte> payload;
  auto operator<=>(const Packet&) const = default;
};
constexpr std::size_t MAX_PACKET_SIZE = 8u * 1024 * 1024;   // 8 MiB
}
