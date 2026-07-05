#include "ed2k/infra/collection.hpp"

#include <variant>

#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::infra {
namespace {
constexpr std::uint32_t collection_magic = 0x4c433245; // E2CL
constexpr std::uint16_t collection_version = 1;

std::string_view trim_line(std::string_view line) {
  while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
    line.remove_suffix(1);
  }
  while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
    line.remove_prefix(1);
  }
  while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) {
    line.remove_suffix(1);
  }
  return line;
}

tl::expected<void, std::error_code> add_link(Collection& collection, std::string_view line) {
  auto parsed = parse_link(line);
  if (!parsed) {
    return tl::unexpected(parsed.error());
  }
  if (!std::holds_alternative<Ed2kFileLink>(*parsed)) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  collection.files.push_back(std::get<Ed2kFileLink>(std::move(*parsed)));
  return {};
}

} // namespace

std::string write_collection_text(const Collection& collection) {
  std::string out;
  for (const auto& file : collection.files) {
    out += to_string(file);
    out += '\n';
  }
  return out;
}

tl::expected<Collection, std::error_code> parse_collection_text(std::string_view text) {
  Collection collection;
  std::size_t pos = 0;
  while (pos < text.size()) {
    const auto end = text.find('\n', pos);
    auto line = trim_line(text.substr(pos, end == std::string_view::npos ? text.size() - pos : end - pos));
    if (!line.empty()) {
      auto added = add_link(collection, line);
      if (!added) {
        return tl::unexpected(added.error());
      }
    }
    if (end == std::string_view::npos) {
      break;
    }
    pos = end + 1;
  }
  return collection;
}

std::vector<std::byte> write_collection_binary(const Collection& collection) {
  codec::ByteWriter w;
  w.u32(collection_magic);
  w.u16(collection_version);
  w.u32(static_cast<std::uint32_t>(collection.files.size()));
  for (const auto& file : collection.files) {
    w.string16(to_string(file));
  }
  return w.take();
}

tl::expected<Collection, std::error_code> parse_collection_binary(std::span<const std::byte> data) {
  codec::ByteReader r(data);
  const auto magic = r.u32();
  const auto version = r.u16();
  const auto count = r.u32();
  if (!r.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (magic != collection_magic) {
    return tl::unexpected(make_error_code(errc::bad_magic));
  }
  if (version != collection_version) {
    return tl::unexpected(make_error_code(errc::unsupported_version));
  }
  if (count > 100000) {
    return tl::unexpected(make_error_code(errc::count_too_large));
  }

  Collection collection;
  collection.files.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    auto link = r.string16();
    if (!r.ok()) {
      return tl::unexpected(make_error_code(errc::buffer_underflow));
    }
    auto added = add_link(collection, link);
    if (!added) {
      return tl::unexpected(added.error());
    }
  }
  return collection;
}

} // namespace ed2k::infra
