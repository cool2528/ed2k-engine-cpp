#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <tl/expected.hpp>

namespace ed2k::infra {

struct Category {
  std::uint32_t id = 0;
  std::string name;
  std::filesystem::path path;
  std::string filter_regex;

  bool operator==(const Category&) const = default;
};

std::vector<std::byte> write_categories(std::span<const Category> categories);
tl::expected<std::vector<Category>, std::error_code>
parse_categories(std::span<const std::byte> data);

class CategoryList {
 public:
  void add(Category category);
  const std::vector<Category>& categories() const noexcept { return categories_; }
  const Category* match(std::string_view filename) const;
  std::filesystem::path archive_path_for(const std::filesystem::path& completed_file) const;

 private:
  std::vector<Category> categories_;
};

} // namespace ed2k::infra
