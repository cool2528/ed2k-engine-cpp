#include "ed2k/kad/nodes_dat.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>

#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::kad {
namespace {
constexpr std::size_t k_contact_wire_size = 25;

std::uint32_t ipv4_to_wire(IPv4 ip) noexcept {
  const auto host = ip.host();
  return ((host & 0x000000ffu) << 24) |
         ((host & 0x0000ff00u) << 8) |
         ((host & 0x00ff0000u) >> 8) |
         ((host & 0xff000000u) >> 24);
}
} // namespace

std::vector<std::byte> write_nodes_dat(std::span<const Contact> contacts) {
  codec::ByteWriter writer;
  writer.u32(nodes_dat_magic);
  writer.u32(static_cast<std::uint32_t>(contacts.size()));
  for (const auto& contact : contacts) {
    writer.blob(contact.id.bytes());
    writer.u32(ipv4_to_wire(contact.ip));
    writer.u16(contact.udp_port);
    writer.u16(contact.tcp_port);
    writer.u8(contact.version);
  }
  return writer.take();
}

tl::expected<std::vector<Contact>, std::error_code> parse_nodes_dat(std::span<const std::byte> data) {
  codec::ByteReader reader(data);
  const auto magic = reader.u32();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (magic != nodes_dat_magic) {
    return tl::unexpected(make_error_code(errc::bad_magic));
  }

  const auto count = reader.u32();
  if (!reader.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }

  if (count > (std::numeric_limits<std::size_t>::max() - 8u) / k_contact_wire_size) {
    return tl::unexpected(make_error_code(errc::count_too_large));
  }
  const auto expected_size = 8u + static_cast<std::size_t>(count) * k_contact_wire_size;
  if (data.size() != expected_size) {
    return tl::unexpected(make_error_code(data.size() < expected_size ? errc::buffer_underflow
                                                                      : errc::count_too_large));
  }

  std::vector<Contact> contacts;
  contacts.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    auto id_blob = reader.blob(KadID::size);
    std::array<std::byte, KadID::size> id_bytes{};
    std::copy(id_blob.begin(), id_blob.end(), id_bytes.begin());

    Contact contact;
    contact.id = KadID::from_bytes(id_bytes);
    contact.ip = IPv4::from_wire(reader.u32());
    contact.udp_port = reader.u16();
    contact.tcp_port = reader.u16();
    contact.version = reader.u8();
    if (!reader.ok()) {
      return tl::unexpected(make_error_code(errc::buffer_underflow));
    }
    contacts.push_back(contact);
  }

  return contacts;
}

} // namespace ed2k::kad
