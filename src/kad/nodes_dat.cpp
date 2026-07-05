#include "ed2k/kad/nodes_dat.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>

#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::kad {
namespace {
constexpr std::size_t k_contact_wire_size = 25;
constexpr std::size_t k_contact_metadata_size = 9;

tl::expected<Contact, std::error_code> read_contact(codec::ByteReader& reader) {
  auto id_blob = reader.blob(KadID::size);
  std::array<std::byte, KadID::size> id_bytes{};
  std::copy(id_blob.begin(), id_blob.end(), id_bytes.begin());

  Contact contact;
  contact.id = kad_id_from_uint128_wire(id_bytes);
  contact.ip = IPv4::from_host(reader.u32());
  contact.udp_port = reader.u16();
  contact.tcp_port = reader.u16();
  contact.version = reader.u8();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  return contact;
}

tl::expected<std::vector<Contact>, std::error_code> parse_contacts(codec::ByteReader& reader,
                                                                    std::uint32_t count,
                                                                    std::size_t metadata_size) {
  const auto record_size = k_contact_wire_size + metadata_size;
  if (record_size == 0 ||
      count > std::numeric_limits<std::size_t>::max() / record_size) {
    return tl::unexpected(make_error_code(errc::count_too_large));
  }

  const auto expected_size = static_cast<std::size_t>(count) * record_size;
  if (reader.remaining() != expected_size) {
    return tl::unexpected(make_error_code(reader.remaining() < expected_size ? errc::buffer_underflow
                                                                             : errc::count_too_large));
  }

  std::vector<Contact> contacts;
  contacts.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    auto contact = read_contact(reader);
    if (!contact) {
      return tl::unexpected(contact.error());
    }
    contacts.push_back(*contact);
    if (metadata_size != 0) {
      (void)reader.blob(metadata_size);
      if (!reader.ok()) {
        return tl::unexpected(make_error_code(errc::buffer_underflow));
      }
    }
  }

  return contacts;
}
} // namespace

std::vector<std::byte> write_nodes_dat(std::span<const Contact> contacts) {
  codec::ByteWriter writer;
  writer.u32(nodes_dat_magic);
  writer.u32(static_cast<std::uint32_t>(contacts.size()));
  for (const auto& contact : contacts) {
    const auto wire_id = kad_id_to_uint128_wire(contact.id);
    writer.blob(wire_id);
    writer.u32(contact.ip.host());
    writer.u16(contact.udp_port);
    writer.u16(contact.tcp_port);
    writer.u8(contact.version);
  }
  return writer.take();
}

tl::expected<std::vector<Contact>, std::error_code> parse_nodes_dat(std::span<const std::byte> data) {
  codec::ByteReader reader(data);
  const auto first = reader.u32();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }

  if (first == nodes_dat_magic) {
    const auto count = reader.u32();
    if (!reader.ok()) {
      return tl::unexpected(make_error_code(errc::buffer_underflow));
    }
    return parse_contacts(reader, count, 0);
  }

  if (first != 0) {
    return parse_contacts(reader, first, 0);
  }

  const auto version = reader.u32();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (version < 1 || version > 3) {
    return tl::unexpected(make_error_code(errc::unsupported_version));
  }

  bool bootstrap_edition = false;
  if (version == 3) {
    const auto edition = reader.u32();
    if (!reader.ok()) {
      return tl::unexpected(make_error_code(errc::buffer_underflow));
    }
    bootstrap_edition = edition == 1;
  }

  const auto count = reader.u32();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }

  const auto metadata_size = version >= 2 && !bootstrap_edition ? k_contact_metadata_size : 0u;
  return parse_contacts(reader, count, metadata_size);
}

} // namespace ed2k::kad
