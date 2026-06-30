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
// 8 MiB：block-level download 每个块 ≤ 180 KiB，远小于 8 MiB，保持 DoS 防护
// P4a 临时提升到 16 MiB 容纳 whole-part download；P4b block-level 恢复原值
constexpr std::size_t MAX_PACKET_SIZE = 8u * 1024 * 1024;   // 8 MiB
}
