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
// 16 MiB：需容纳单个 eD2k part（PART_SIZE = 9728000 ≈ 9.28 MiB）的 SENDINGPART
// （整 part 作为单块下载时帧体 ≈ 9.28 MiB + 头部开销），仍可拦截恶意 4 GiB 帧。
constexpr std::size_t MAX_PACKET_SIZE = 16u * 1024 * 1024;   // 16 MiB
}
