#pragma once
#include <cstddef>
#include <span>
#include <vector>
#include <system_error>
#include <tl/expected.hpp>
#include "ed2k/net/packet.hpp"
namespace ed2k::net {
// UDP 数据报编解码（无 size 字段）：[1B protocol][1B opcode][payload]
// 0xD4 eMule 压缩变体：[0xD4][opcode][zlib-compressed-payload]，解压后 protocol 归一化为 0xC5
// 0xE5 Kad 压缩变体：[0xE5][opcode][zlib-compressed-payload]，解压后 protocol 归一化为 0xE4
std::vector<std::byte> encode_udp_packet(const Packet&);
tl::expected<Packet,std::error_code> parse_udp_datagram(std::span<const std::byte> data);
}
