#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <tl/expected.hpp>

#include "ed2k/link/ed2k_link.hpp"

namespace ed2k::infra {

struct Collection {
  std::vector<Ed2kFileLink> files;
};

std::string write_collection_text(const Collection& collection);
tl::expected<Collection, std::error_code> parse_collection_text(std::string_view text);

std::vector<std::byte> write_collection_binary(const Collection& collection);
tl::expected<Collection, std::error_code> parse_collection_binary(std::span<const std::byte> data);

} // namespace ed2k::infra
