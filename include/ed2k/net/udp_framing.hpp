#pragma once
#include <cstddef>
#include <span>
#include <vector>
#include <system_error>
#include <tl/expected.hpp>
#include "ed2k/net/packet.hpp"
namespace ed2k::net {
// UDP datagram encode/decode (no size field): [1B protocol][1B opcode][payload]
// 0xD4 eMule compressed variant: [0xD4][opcode][zlib-compressed-payload], after decompression protocol normalizes to 0xC5
// 0xE5 Kad compressed variant: [0xE5][opcode][zlib-compressed-payload], after decompression protocol normalizes to 0xE4
std::vector<std::byte> encode_udp_packet(const Packet&);
tl::expected<Packet,std::error_code> parse_udp_datagram(std::span<const std::byte> data);
}
