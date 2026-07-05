#include "ed2k/kad/messages.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <utility>
#include <variant>

#include "ed2k/codec/byte_io.hpp"
#include "ed2k/codec/tag.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::kad {
namespace {
constexpr std::size_t k_contact_wire_size = 25;
constexpr std::uint8_t k_tag_kad_misc_options = 0xF2;
constexpr std::uint8_t k_tag_source_udp_port = 0xFC;

std::uint32_t ipv4_to_wire(IPv4 ip) noexcept {
  const auto host = ip.host();
  return ((host & 0x000000ffu) << 24) |
         ((host & 0x0000ff00u) << 8) |
         ((host & 0x00ff0000u) >> 8) |
         ((host & 0xff000000u) >> 24);
}

bool has_name_id(const codec::Tag& tag, std::uint8_t name_id) noexcept {
  if (tag.name_id == name_id) {
    return true;
  }
  if (tag.name_str.size() != 1) {
    return false;
  }
  return static_cast<std::uint8_t>(static_cast<unsigned char>(tag.name_str[0])) == name_id;
}

std::uint64_t integer_value(const codec::Tag& tag) noexcept {
  if (const auto* value = std::get_if<std::uint64_t>(&tag.value)) {
    return *value;
  }
  return 0;
}

tl::expected<void, std::error_code> require_packet(const net::Packet& packet, std::uint8_t opcode) {
  if (packet.protocol != kad_protocol || packet.opcode != opcode) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  return {};
}

tl::expected<void, std::error_code> require_hello_packet(const net::Packet& packet) {
  if (packet.protocol != kad_protocol ||
      (packet.opcode != opcode::kad2_hello_req && packet.opcode != opcode::kad2_hello_res)) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  return {};
}

tl::expected<KadID, std::error_code> read_kad_id(codec::ByteReader& reader) {
  auto id_blob = reader.blob(KadID::size);
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }

  std::array<std::byte, KadID::size> id_bytes{};
  std::copy(id_blob.begin(), id_blob.end(), id_bytes.begin());
  return KadID::from_bytes(id_bytes);
}

void write_contact(codec::ByteWriter& writer, const Contact& contact) {
  writer.blob(contact.id.bytes());
  writer.u32(ipv4_to_wire(contact.ip));
  writer.u16(contact.udp_port);
  writer.u16(contact.tcp_port);
  writer.u8(contact.version);
}

tl::expected<Contact, std::error_code> read_contact(codec::ByteReader& reader) {
  auto id = read_kad_id(reader);
  if (!id) {
    return tl::unexpected(id.error());
  }

  Contact contact;
  contact.id = *id;
  contact.ip = IPv4::from_wire(reader.u32());
  contact.udp_port = reader.u16();
  contact.tcp_port = reader.u16();
  contact.version = reader.u8();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  return contact;
}

net::Packet make_packet(std::uint8_t opcode, std::vector<std::byte> payload) {
  net::Packet packet;
  packet.protocol = kad_protocol;
  packet.opcode = opcode;
  packet.payload = std::move(payload);
  return packet;
}

net::Packet encode_hello(std::uint8_t opcode, const Contact& self) {
  codec::ByteWriter writer;
  writer.blob(self.id.bytes());
  writer.u16(self.tcp_port);
  writer.u8(self.version);
  writer.u8(0); // tag count; no SOURCEUPORT/KADMISCOPTIONS tag needed for default ports.
  return make_packet(opcode, writer.take());
}
} // namespace

net::Packet encode_kad2_hello_req(const Contact& self) {
  return encode_hello(opcode::kad2_hello_req, self);
}

net::Packet encode_kad2_hello_res(const Contact& self) {
  return encode_hello(opcode::kad2_hello_res, self);
}

tl::expected<Contact, std::error_code> decode_kad2_hello(const net::Packet& packet,
                                                          IPv4 sender_ip,
                                                          std::uint16_t sender_udp_port) {
  auto ok = require_hello_packet(packet);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  auto id = read_kad_id(reader);
  if (!id) {
    return tl::unexpected(id.error());
  }

  Contact contact;
  contact.id = *id;
  contact.ip = sender_ip;
  contact.udp_port = sender_udp_port;
  contact.tcp_port = reader.u16();
  contact.version = reader.u8();
  const auto tag_count = reader.u8();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (contact.version < 2) {
    return tl::unexpected(make_error_code(errc::unsupported_version));
  }

  for (std::uint8_t i = 0; i < tag_count; ++i) {
    auto tag = codec::read_tag(reader);
    if (!tag) {
      return tl::unexpected(tag.error());
    }
    if (has_name_id(*tag, k_tag_source_udp_port)) {
      const auto port = integer_value(*tag);
      if (port > 0 && port <= std::numeric_limits<std::uint16_t>::max()) {
        contact.udp_port = static_cast<std::uint16_t>(port);
      }
    } else if (has_name_id(*tag, k_tag_kad_misc_options)) {
      (void)integer_value(*tag);
    }
  }

  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() != 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  return contact;
}

net::Packet encode_kad2_req(const KadID& target, const KadID& receiver_id, std::uint8_t count) {
  codec::ByteWriter writer;
  writer.u8(static_cast<std::uint8_t>(count & 0x1Fu));
  writer.blob(target.bytes());
  writer.blob(receiver_id.bytes());
  return make_packet(opcode::kad2_req, writer.take());
}

tl::expected<Kad2Request, std::error_code> decode_kad2_req(const net::Packet& packet) {
  auto ok = require_packet(packet, opcode::kad2_req);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  Kad2Request request;
  request.count = static_cast<std::uint8_t>(reader.u8() & 0x1Fu);
  auto target = read_kad_id(reader);
  if (!target) {
    return tl::unexpected(target.error());
  }
  auto receiver_id = read_kad_id(reader);
  if (!receiver_id) {
    return tl::unexpected(receiver_id.error());
  }
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() != 0 || request.count == 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  request.target = *target;
  request.receiver_id = *receiver_id;
  return request;
}

net::Packet encode_kad2_res(const KadID& target, std::span<const Contact> contacts) {
  const auto count = std::min<std::size_t>(contacts.size(), std::numeric_limits<std::uint8_t>::max());

  codec::ByteWriter writer;
  writer.blob(target.bytes());
  writer.u8(static_cast<std::uint8_t>(count));
  for (std::size_t i = 0; i < count; ++i) {
    write_contact(writer, contacts[i]);
  }
  return make_packet(opcode::kad2_res, writer.take());
}

tl::expected<Kad2Response, std::error_code> decode_kad2_res(const net::Packet& packet) {
  auto ok = require_packet(packet, opcode::kad2_res);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  auto target = read_kad_id(reader);
  if (!target) {
    return tl::unexpected(target.error());
  }
  const auto count = reader.u8();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() != static_cast<std::size_t>(count) * k_contact_wire_size) {
    return tl::unexpected(make_error_code(reader.remaining() < static_cast<std::size_t>(count) * k_contact_wire_size
                                             ? errc::buffer_underflow
                                             : errc::server_protocol_error));
  }

  Kad2Response response;
  response.target = *target;
  response.contacts.reserve(count);
  for (std::uint8_t i = 0; i < count; ++i) {
    auto contact = read_contact(reader);
    if (!contact) {
      return tl::unexpected(contact.error());
    }
    response.contacts.push_back(*contact);
  }
  return response;
}

} // namespace ed2k::kad
