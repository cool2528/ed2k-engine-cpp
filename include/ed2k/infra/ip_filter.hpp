#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <tl/expected.hpp>

#include "ed2k/core/hash.hpp"

namespace ed2k::infra {

struct IPRange {
  IPv4 start;
  IPv4 end;
  std::uint8_t level = 0;
  std::string name;

  bool contains(IPv4 ip) const noexcept {
    return start.host() <= ip.host() && ip.host() <= end.host();
  }
};

class IPFilter {
 public:
  static tl::expected<IPFilter, std::error_code> parse(std::string_view text);
  static tl::expected<IPFilter, std::error_code> load(const std::filesystem::path& path);

  void add(IPRange range);
  bool blocked(IPv4 ip, std::uint8_t threshold = 127) const noexcept;
  const std::vector<IPRange>& ranges() const noexcept { return ranges_; }

 private:
  void rebuild_index();
  std::vector<IPRange> ranges_;
  std::vector<std::uint32_t> max_end_prefix_;
};

} // namespace ed2k::infra
