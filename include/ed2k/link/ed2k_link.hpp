#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/util/error.hpp"
namespace ed2k {
struct Ed2kFileLink {
  std::string name; std::uint64_t size=0; FileHash hash;
  std::optional<AICHHash> aich; std::vector<PartHash> part_hashes;
  std::vector<std::string> sources;
};
struct ServerLink { IPv4 ip; std::uint16_t port=0; };
struct ServerListLink { std::string url; };
using Ed2kLink = std::variant<Ed2kFileLink,ServerLink,ServerListLink>;
tl::expected<Ed2kLink,std::error_code> parse_link(std::string_view);
std::string to_string(const Ed2kFileLink&);
}
