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
// 8 MiB: block-level download blocks are <= 180 KiB each, well under 8 MiB; keeps DoS protection
// P4a temporarily raised to 16 MiB for whole-part download; P4b block-level restored the original value
constexpr std::size_t MAX_PACKET_SIZE = 8u * 1024 * 1024;   // 8 MiB
}
