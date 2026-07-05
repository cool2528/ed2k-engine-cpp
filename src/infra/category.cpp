#include "ed2k/infra/category.hpp"

#include <regex>

#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::infra {
namespace {
constexpr std::uint32_t category_magic = 0x54433245; // E2CT
constexpr std::uint16_t category_version = 1;

std::string path_string(const std::filesystem::path& path) {
  return path.generic_string();
}
} // namespace

std::vector<std::byte> write_categories(std::span<const Category> categories) {
  codec::ByteWriter w;
  w.u32(category_magic);
  w.u16(category_version);
  w.u32(static_cast<std::uint32_t>(categories.size()));
  for (const auto& category : categories) {
    w.u32(category.id);
    w.string16(category.name);
    w.string16(path_string(category.path));
    w.string16(category.filter_regex);
  }
  return w.take();
}

tl::expected<std::vector<Category>, std::error_code>
parse_categories(std::span<const std::byte> data) {
  codec::ByteReader r(data);
  const auto magic = r.u32();
  const auto version = r.u16();
  const auto count = r.u32();
  if (!r.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (magic != category_magic) {
    return tl::unexpected(make_error_code(errc::bad_magic));
  }
  if (version != category_version) {
    return tl::unexpected(make_error_code(errc::unsupported_version));
  }
  if (count > 100000) {
    return tl::unexpected(make_error_code(errc::count_too_large));
  }

  std::vector<Category> out;
  out.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    Category category;
    category.id = r.u32();
    category.name = r.string16();
    category.path = r.string16();
    category.filter_regex = r.string16();
    if (!r.ok()) {
      return tl::unexpected(make_error_code(errc::buffer_underflow));
    }
    out.push_back(std::move(category));
  }
  return out;
}

void CategoryList::add(Category category) {
  categories_.push_back(std::move(category));
}

const Category* CategoryList::match(std::string_view filename) const {
  const std::string name(filename);
  for (const auto& category : categories_) {
    try {
      const std::regex filter(category.filter_regex, std::regex::ECMAScript | std::regex::icase);
      if (std::regex_match(name, filter)) {
        return &category;
      }
    } catch (const std::regex_error&) {
      continue;
    }
  }
  return nullptr;
}

std::filesystem::path CategoryList::archive_path_for(const std::filesystem::path& completed_file) const {
  const auto filename = completed_file.filename();
  const auto* category = match(filename.generic_string());
  if (!category) {
    return completed_file;
  }
  return category->path / filename;
}

} // namespace ed2k::infra
