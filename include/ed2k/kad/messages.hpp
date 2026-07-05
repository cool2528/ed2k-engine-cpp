#pragma once

#include <cstdint>
#include <span>
#include <system_error>
#include <vector>

#include <tl/expected.hpp>

#include "ed2k/kad/routing_table.hpp"
#include "ed2k/net/packet.hpp"

namespace ed2k::kad {

inline constexpr std::uint8_t kad_protocol = 0xE4;
inline constexpr std::uint8_t kad_packed_protocol = 0xE5;
inline constexpr std::uint8_t kad2_version = 0x08;

namespace opcode {
inline constexpr std::uint8_t kad2_bootstrap_req = 0x01;
inline constexpr std::uint8_t kad2_bootstrap_res = 0x09;
inline constexpr std::uint8_t kad2_hello_req = 0x11;
inline constexpr std::uint8_t kad2_hello_res = 0x19;
inline constexpr std::uint8_t kad2_req = 0x21;
inline constexpr std::uint8_t kad2_hello_res_ack = 0x22;
inline constexpr std::uint8_t kad2_res = 0x29;
} // namespace opcode

struct Kad2Request {
  std::uint8_t count = 0;
  KadID target;
  KadID receiver_id;
};

struct Kad2Response {
  KadID target;
  std::vector<Contact> contacts;
};

net::Packet encode_kad2_hello_req(const Contact& self);
net::Packet encode_kad2_hello_res(const Contact& self);
tl::expected<Contact, std::error_code> decode_kad2_hello(const net::Packet& packet,
                                                          IPv4 sender_ip,
                                                          std::uint16_t sender_udp_port);

net::Packet encode_kad2_req(const KadID& target, const KadID& receiver_id, std::uint8_t count);
tl::expected<Kad2Request, std::error_code> decode_kad2_req(const net::Packet& packet);

net::Packet encode_kad2_res(const KadID& target, std::span<const Contact> contacts);
tl::expected<Kad2Response, std::error_code> decode_kad2_res(const net::Packet& packet);

} // namespace ed2k::kad
