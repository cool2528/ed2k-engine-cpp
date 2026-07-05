#include "ed2k/kad/messages.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <string>
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

std::string string_value(const codec::Tag& tag) {
  if (const auto* value = std::get_if<std::string>(&tag.value)) {
    return *value;
  }
  return {};
}

const codec::Tag* find_tag(const KadSearchEntry& entry, std::uint8_t name_id) noexcept {
  for (const auto& tag_value : entry.tags) {
    if (has_name_id(tag_value, name_id)) {
      return &tag_value;
    }
  }
  return nullptr;
}

tl::expected<void, std::error_code> require_packet(const net::Packet& packet, std::uint8_t opcode) {
  if (packet.protocol != kad_protocol || packet.opcode != opcode) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  return {};
}

tl::expected<void, std::error_code> require_exact_payload(const net::Packet& packet,
                                                          std::uint8_t opcode,
                                                          std::size_t size) {
  auto ok = require_packet(packet, opcode);
  if (!ok) {
    return tl::unexpected(ok.error());
  }
  if (packet.payload.size() != size) {
    return tl::unexpected(make_error_code(packet.payload.size() < size ? errc::buffer_underflow
                                                                       : errc::server_protocol_error));
  }
  return {};
}

tl::expected<void, std::error_code> require_min_payload(const net::Packet& packet,
                                                        std::uint8_t opcode,
                                                        std::size_t size) {
  auto ok = require_packet(packet, opcode);
  if (!ok) {
    return tl::unexpected(ok.error());
  }
  if (packet.payload.size() < size) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
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

void write_tag_list(codec::ByteWriter& writer, std::span<const codec::Tag> tags) {
  const auto count = std::min<std::size_t>(tags.size(), std::numeric_limits<std::uint8_t>::max());
  writer.u8(static_cast<std::uint8_t>(count));
  for (std::size_t i = 0; i < count; ++i) {
    codec::write_tag(writer, tags[i]);
  }
}

tl::expected<std::vector<codec::Tag>, std::error_code> read_tag_list(codec::ByteReader& reader) {
  const auto count = reader.u8();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  return codec::read_taglist(reader, count);
}

void write_search_entry(codec::ByteWriter& writer, const KadSearchEntry& entry) {
  writer.blob(entry.answer_id.bytes());
  write_tag_list(writer, entry.tags);
}

tl::expected<KadSearchEntry, std::error_code> read_search_entry(codec::ByteReader& reader) {
  auto answer = read_kad_id(reader);
  if (!answer) {
    return tl::unexpected(answer.error());
  }
  auto tags = read_tag_list(reader);
  if (!tags) {
    return tl::unexpected(tags.error());
  }

  KadSearchEntry entry;
  entry.answer_id = *answer;
  entry.tags = std::move(*tags);
  return entry;
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

net::Packet encode_kad2_search_key_req(const KadID& target, std::uint16_t start_position) {
  codec::ByteWriter writer;
  writer.blob(target.bytes());
  writer.u16(static_cast<std::uint16_t>(start_position & 0x7fffu));
  return make_packet(opcode::kad2_search_key_req, writer.take());
}

tl::expected<KadSearchRequest, std::error_code> decode_kad2_search_key_req(const net::Packet& packet) {
  auto ok = require_packet(packet, opcode::kad2_search_key_req);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  auto target = read_kad_id(reader);
  if (!target) {
    return tl::unexpected(target.error());
  }
  const auto start = reader.u16();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if ((start & 0x8000u) != 0 || reader.remaining() != 0) {
    return tl::unexpected(make_error_code(errc::unsupported_version));
  }

  KadSearchRequest request;
  request.target = *target;
  request.start_position = static_cast<std::uint16_t>(start & 0x7fffu);
  return request;
}

net::Packet encode_kad2_search_source_req(const KadID& target, std::uint16_t start_position,
                                           std::uint64_t file_size) {
  codec::ByteWriter writer;
  writer.blob(target.bytes());
  writer.u16(static_cast<std::uint16_t>(start_position & 0x7fffu));
  writer.u64(file_size);
  return make_packet(opcode::kad2_search_source_req, writer.take());
}

tl::expected<KadSearchRequest, std::error_code> decode_kad2_search_source_req(const net::Packet& packet) {
  auto ok = require_packet(packet, opcode::kad2_search_source_req);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  auto target = read_kad_id(reader);
  if (!target) {
    return tl::unexpected(target.error());
  }
  KadSearchRequest request;
  request.target = *target;
  request.start_position = static_cast<std::uint16_t>(reader.u16() & 0x7fffu);
  request.file_size = reader.u64();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() != 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  return request;
}

net::Packet encode_kad2_search_notes_req(const KadID& target, std::uint64_t file_size) {
  codec::ByteWriter writer;
  writer.blob(target.bytes());
  writer.u64(file_size);
  return make_packet(opcode::kad2_search_notes_req, writer.take());
}

tl::expected<KadSearchRequest, std::error_code> decode_kad2_search_notes_req(const net::Packet& packet) {
  auto ok = require_packet(packet, opcode::kad2_search_notes_req);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  auto target = read_kad_id(reader);
  if (!target) {
    return tl::unexpected(target.error());
  }
  KadSearchRequest request;
  request.target = *target;
  request.file_size = reader.u64();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() != 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  return request;
}

net::Packet encode_kad2_search_res(const KadID& sender_id, const KadID& target,
                                    std::span<const KadSearchEntry> entries) {
  const auto count = std::min<std::size_t>(entries.size(), std::numeric_limits<std::uint16_t>::max());

  codec::ByteWriter writer;
  writer.blob(sender_id.bytes());
  writer.blob(target.bytes());
  writer.u16(static_cast<std::uint16_t>(count));
  for (std::size_t i = 0; i < count; ++i) {
    write_search_entry(writer, entries[i]);
  }
  return make_packet(opcode::kad2_search_res, writer.take());
}

tl::expected<KadSearchResponse, std::error_code> decode_kad2_search_res(const net::Packet& packet) {
  auto ok = require_packet(packet, opcode::kad2_search_res);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  auto sender = read_kad_id(reader);
  if (!sender) {
    return tl::unexpected(sender.error());
  }
  auto target = read_kad_id(reader);
  if (!target) {
    return tl::unexpected(target.error());
  }
  const auto count = reader.u16();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }

  KadSearchResponse response;
  response.sender_id = *sender;
  response.target = *target;
  response.entries.reserve(count);
  for (std::uint16_t i = 0; i < count; ++i) {
    auto entry = read_search_entry(reader);
    if (!entry) {
      return tl::unexpected(entry.error());
    }
    response.entries.push_back(std::move(*entry));
  }
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() != 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  return response;
}

net::Packet encode_kad2_publish_key_req(const KadID& key_id, std::span<const KadSearchEntry> entries) {
  const auto count = std::min<std::size_t>(entries.size(), std::numeric_limits<std::uint16_t>::max());

  codec::ByteWriter writer;
  writer.blob(key_id.bytes());
  writer.u16(static_cast<std::uint16_t>(count));
  for (std::size_t i = 0; i < count; ++i) {
    write_search_entry(writer, entries[i]);
  }
  return make_packet(opcode::kad2_publish_key_req, writer.take());
}

tl::expected<KadPublishKeyRequest, std::error_code> decode_kad2_publish_key_req(const net::Packet& packet) {
  auto ok = require_packet(packet, opcode::kad2_publish_key_req);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  auto key = read_kad_id(reader);
  if (!key) {
    return tl::unexpected(key.error());
  }
  const auto count = reader.u16();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }

  KadPublishKeyRequest request;
  request.key_id = *key;
  request.entries.reserve(count);
  for (std::uint16_t i = 0; i < count; ++i) {
    auto entry = read_search_entry(reader);
    if (!entry) {
      return tl::unexpected(entry.error());
    }
    request.entries.push_back(std::move(*entry));
  }
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() != 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  return request;
}

net::Packet encode_kad2_publish_source_req(const KadID& file_id, const KadSearchEntry& source) {
  codec::ByteWriter writer;
  writer.blob(file_id.bytes());
  write_search_entry(writer, source);
  return make_packet(opcode::kad2_publish_source_req, writer.take());
}

tl::expected<KadPublishSourceRequest, std::error_code> decode_kad2_publish_source_req(const net::Packet& packet) {
  auto ok = require_packet(packet, opcode::kad2_publish_source_req);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  auto file = read_kad_id(reader);
  if (!file) {
    return tl::unexpected(file.error());
  }
  auto source = read_search_entry(reader);
  if (!source) {
    return tl::unexpected(source.error());
  }
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() != 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  KadPublishSourceRequest request;
  request.file_id = *file;
  request.source = std::move(*source);
  return request;
}

net::Packet encode_kad2_publish_notes_req(const KadID& file_id, const KadSearchEntry& note) {
  codec::ByteWriter writer;
  writer.blob(file_id.bytes());
  write_search_entry(writer, note);
  return make_packet(opcode::kad2_publish_notes_req, writer.take());
}

tl::expected<KadPublishNotesRequest, std::error_code> decode_kad2_publish_notes_req(const net::Packet& packet) {
  auto ok = require_packet(packet, opcode::kad2_publish_notes_req);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  auto file = read_kad_id(reader);
  if (!file) {
    return tl::unexpected(file.error());
  }
  auto note = read_search_entry(reader);
  if (!note) {
    return tl::unexpected(note.error());
  }
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() != 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  KadPublishNotesRequest request;
  request.file_id = *file;
  request.note = std::move(*note);
  return request;
}

net::Packet encode_kad2_publish_res(const KadID& target, std::uint8_t load) {
  codec::ByteWriter writer;
  writer.blob(target.bytes());
  writer.u8(load);
  return make_packet(opcode::kad2_publish_res, writer.take());
}

tl::expected<KadPublishResponse, std::error_code> decode_kad2_publish_res(const net::Packet& packet) {
  auto ok = require_packet(packet, opcode::kad2_publish_res);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  auto target = read_kad_id(reader);
  if (!target) {
    return tl::unexpected(target.error());
  }
  KadPublishResponse response;
  response.target = *target;
  response.load = reader.u8();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() > 0) {
    const auto options = reader.u8();
    response.requests_ack = (options & 0x01u) != 0;
  }
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() != 0) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  return response;
}

net::Packet encode_kademlia_firewalled_req(std::uint16_t tcp_port) {
  codec::ByteWriter writer;
  writer.u16(tcp_port);
  return make_packet(opcode::kademlia_firewalled_req, writer.take());
}

tl::expected<KadFirewalledRequest, std::error_code> decode_kademlia_firewalled_req(const net::Packet& packet) {
  auto ok = require_exact_payload(packet, opcode::kademlia_firewalled_req, 2);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  KadFirewalledRequest request;
  request.tcp_port = reader.u16();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  return request;
}

net::Packet encode_kademlia_firewalled2_req(std::uint16_t tcp_port, const KadID& user_hash,
                                             std::uint8_t connect_options) {
  codec::ByteWriter writer;
  writer.u16(tcp_port);
  writer.blob(user_hash.bytes());
  writer.u8(connect_options);
  return make_packet(opcode::kademlia_firewalled2_req, writer.take());
}

tl::expected<KadFirewalledRequest, std::error_code> decode_kademlia_firewalled2_req(const net::Packet& packet) {
  auto ok = require_min_payload(packet, opcode::kademlia_firewalled2_req, 19);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  KadFirewalledRequest request;
  request.tcp_port = reader.u16();
  auto user_hash = read_kad_id(reader);
  if (!user_hash) {
    return tl::unexpected(user_hash.error());
  }
  request.user_hash = *user_hash;
  request.connect_options = reader.u8();
  request.has_user_hash = true;
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  return request;
}

net::Packet encode_kademlia_firewalled_res(IPv4 ip) {
  codec::ByteWriter writer;
  writer.u32(ipv4_to_wire(ip));
  return make_packet(opcode::kademlia_firewalled_res, writer.take());
}

tl::expected<KadFirewalledResponse, std::error_code> decode_kademlia_firewalled_res(const net::Packet& packet) {
  auto ok = require_exact_payload(packet, opcode::kademlia_firewalled_res, 4);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  KadFirewalledResponse response;
  response.ip = IPv4::from_wire(reader.u32());
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  return response;
}

net::Packet encode_kademlia_firewalled_ack_res() {
  return make_packet(opcode::kademlia_firewalled_ack_res, {});
}

tl::expected<void, std::error_code> decode_kademlia_firewalled_ack_res(const net::Packet& packet) {
  return require_exact_payload(packet, opcode::kademlia_firewalled_ack_res, 0);
}

net::Packet encode_kad2_firewall_udp(std::uint8_t error_code, std::uint16_t incoming_port) {
  codec::ByteWriter writer;
  writer.u8(error_code);
  writer.u16(incoming_port);
  return make_packet(opcode::kad2_firewall_udp, writer.take());
}

tl::expected<KadFirewallUdp, std::error_code> decode_kad2_firewall_udp(const net::Packet& packet) {
  auto ok = require_min_payload(packet, opcode::kad2_firewall_udp, 3);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  KadFirewallUdp result;
  result.error_code = reader.u8();
  result.incoming_port = reader.u16();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  return result;
}

net::Packet encode_kademlia_find_buddy_req(const KadID& buddy_id, const KadID& user_hash,
                                            std::uint16_t tcp_port) {
  codec::ByteWriter writer;
  writer.blob(buddy_id.bytes());
  writer.blob(user_hash.bytes());
  writer.u16(tcp_port);
  return make_packet(opcode::kademlia_find_buddy_req, writer.take());
}

net::Packet encode_kademlia_find_buddy_res(const KadID& buddy_id, const KadID& user_hash,
                                            std::uint16_t tcp_port) {
  codec::ByteWriter writer;
  writer.blob(buddy_id.bytes());
  writer.blob(user_hash.bytes());
  writer.u16(tcp_port);
  return make_packet(opcode::kademlia_find_buddy_res, writer.take());
}

net::Packet encode_kademlia_find_buddy_res(const KadID& buddy_id, const KadID& user_hash,
                                            std::uint16_t tcp_port, std::uint8_t connect_options) {
  codec::ByteWriter writer;
  writer.blob(buddy_id.bytes());
  writer.blob(user_hash.bytes());
  writer.u16(tcp_port);
  writer.u8(connect_options);
  return make_packet(opcode::kademlia_find_buddy_res, writer.take());
}

tl::expected<KadBuddyMessage, std::error_code> decode_buddy_message(const net::Packet& packet,
                                                                    std::uint8_t opcode_value) {
  auto ok = require_min_payload(packet, opcode_value, 34);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  KadBuddyMessage message;
  auto buddy_id = read_kad_id(reader);
  if (!buddy_id) {
    return tl::unexpected(buddy_id.error());
  }
  auto user_hash = read_kad_id(reader);
  if (!user_hash) {
    return tl::unexpected(user_hash.error());
  }
  message.buddy_id = *buddy_id;
  message.user_hash = *user_hash;
  message.tcp_port = reader.u16();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (reader.remaining() > 0) {
    message.connect_options = reader.u8();
    message.has_connect_options = true;
  }
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  return message;
}

tl::expected<KadBuddyMessage, std::error_code> decode_kademlia_find_buddy_req(const net::Packet& packet) {
  return decode_buddy_message(packet, opcode::kademlia_find_buddy_req);
}

tl::expected<KadBuddyMessage, std::error_code> decode_kademlia_find_buddy_res(const net::Packet& packet) {
  return decode_buddy_message(packet, opcode::kademlia_find_buddy_res);
}

net::Packet encode_kademlia_callback_req(const KadID& buddy_id, const KadID& file_id,
                                          std::uint16_t tcp_port) {
  codec::ByteWriter writer;
  writer.blob(buddy_id.bytes());
  writer.blob(file_id.bytes());
  writer.u16(tcp_port);
  return make_packet(opcode::kademlia_callback_req, writer.take());
}

tl::expected<KadCallbackRequest, std::error_code> decode_kademlia_callback_req(const net::Packet& packet) {
  auto ok = require_min_payload(packet, opcode::kademlia_callback_req, 34);
  if (!ok) {
    return tl::unexpected(ok.error());
  }

  codec::ByteReader reader(packet.payload);
  KadCallbackRequest request;
  auto buddy_id = read_kad_id(reader);
  if (!buddy_id) {
    return tl::unexpected(buddy_id.error());
  }
  auto file_id = read_kad_id(reader);
  if (!file_id) {
    return tl::unexpected(file_id.error());
  }
  request.buddy_id = *buddy_id;
  request.file_id = *file_id;
  request.tcp_port = reader.u16();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  return request;
}

std::string file_name(const KadSearchEntry& entry) {
  if (const auto* tag_value = find_tag(entry, tag::filename)) {
    return string_value(*tag_value);
  }
  return {};
}

std::uint64_t file_size(const KadSearchEntry& entry) noexcept {
  if (const auto* tag_value = find_tag(entry, tag::file_size)) {
    return integer_value(*tag_value);
  }
  return 0;
}

std::uint16_t source_tcp_port(const KadSearchEntry& entry) noexcept {
  if (const auto* tag_value = find_tag(entry, tag::source_port)) {
    return static_cast<std::uint16_t>(integer_value(*tag_value));
  }
  return 0;
}

std::uint16_t source_udp_port(const KadSearchEntry& entry) noexcept {
  if (const auto* tag_value = find_tag(entry, tag::source_udp_port)) {
    return static_cast<std::uint16_t>(integer_value(*tag_value));
  }
  return 0;
}

} // namespace ed2k::kad
