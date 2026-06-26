#pragma once
#include <cstdint>
#include <span>
#include <vector>
#include <system_error>
#include <tl/expected.hpp>
#include "ed2k/net/packet.hpp"
namespace ed2k::net {
struct FrameHeader { std::uint8_t protocol; std::uint32_t size; };  // size = opcode(1) + payload
std::vector<std::byte> encode_frame(const Packet&);
tl::expected<FrameHeader,std::error_code> parse_header(std::span<const std::byte,5>);
tl::expected<Packet,std::error_code> assemble(std::uint8_t protocol, std::span<const std::byte> body);
}
