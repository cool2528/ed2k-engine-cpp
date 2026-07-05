#include "ed2k/infra/ip_filter.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <limits>
#include <string>

#include "ed2k/util/error.hpp"

namespace ed2k::infra {
namespace {

std::string_view trim(std::string_view s) noexcept {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) {
    s.remove_prefix(1);
  }
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
    s.remove_suffix(1);
  }
  return s;
}

bool starts_with(std::string_view s, std::string_view prefix) noexcept {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

std::string_view strip_quotes(std::string_view s) noexcept {
  s = trim(s);
  if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
    s.remove_prefix(1);
    s.remove_suffix(1);
  }
  return s;
}

tl::expected<unsigned, std::error_code> parse_uint(std::string_view s) {
  s = trim(s);
  if (s.empty()) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  unsigned value = 0;
  const char* first = s.data();
  const char* last = s.data() + s.size();
  auto [ptr, ec] = std::from_chars(first, last, value);
  if (ec != std::errc{} || ptr != last) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  return value;
}

tl::expected<IPv4, std::error_code> parse_ip(std::string_view s) {
  auto ip = IPv4::from_dotted(trim(s));
  if (!ip) {
    return tl::unexpected(ip.error());
  }
  return *ip;
}

std::pair<std::string_view, std::string_view> split_once(std::string_view s, char delim) noexcept {
  const auto pos = s.find(delim);
  if (pos == std::string_view::npos) {
    return {trim(s), std::string_view{}};
  }
  return {trim(s.substr(0, pos)), s.substr(pos + 1)};
}

tl::expected<IPRange, std::error_code> parse_cidr_line(std::string_view line) {
  auto [cidr, rest] = split_once(line, ',');
  auto [level_s, name_s] = split_once(rest, ',');
  auto [base_s, prefix_s] = split_once(cidr, '/');
  if (rest.empty() || level_s.empty() || prefix_s.empty()) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  auto base = parse_ip(base_s);
  if (!base) {
    return tl::unexpected(base.error());
  }
  auto prefix = parse_uint(prefix_s);
  if (!prefix || *prefix > 32) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  auto level = parse_uint(level_s);
  if (!level || *level > std::numeric_limits<std::uint8_t>::max()) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  const std::uint32_t mask = *prefix == 0 ? 0u : (0xffffffffu << (32u - *prefix));
  const std::uint32_t start = base->host() & mask;
  const std::uint32_t end = start | ~mask;
  return IPRange{
      .start = IPv4::from_host(start),
      .end = IPv4::from_host(end),
      .level = static_cast<std::uint8_t>(*level),
      .name = std::string(strip_quotes(name_s)),
  };
}

tl::expected<IPRange, std::error_code> parse_range_line(std::string_view line) {
  auto [start_s, rest1] = split_once(line, ',');
  auto [end_s, rest2] = split_once(rest1, ',');
  auto [level_s, name_s] = split_once(rest2, ',');
  if (rest1.empty() || rest2.empty() || level_s.empty()) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  auto start = parse_ip(start_s);
  auto end = parse_ip(end_s);
  auto level = parse_uint(level_s);
  if (!start) {
    return tl::unexpected(start.error());
  }
  if (!end) {
    return tl::unexpected(end.error());
  }
  if (!level || *level > std::numeric_limits<std::uint8_t>::max()) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  if (start->host() > end->host()) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  return IPRange{
      .start = *start,
      .end = *end,
      .level = static_cast<std::uint8_t>(*level),
      .name = std::string(strip_quotes(name_s)),
  };
}

} // namespace

tl::expected<IPFilter, std::error_code> IPFilter::parse(std::string_view text) {
  IPFilter filter;
  while (!text.empty()) {
    auto [line, rest] = split_once(text, '\n');
    text = rest;
    if (starts_with(line, "\xef\xbb\xbf")) {
      line.remove_prefix(3);
      line = trim(line);
    }
    if (line.empty() || starts_with(line, "#") || starts_with(line, "//")) {
      continue;
    }

    auto range = line.find('/') != std::string_view::npos ? parse_cidr_line(line) : parse_range_line(line);
    if (!range) {
      return tl::unexpected(range.error());
    }
    filter.add(std::move(*range));
  }
  return filter;
}

tl::expected<IPFilter, std::error_code> IPFilter::load(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return tl::unexpected(make_error_code(errc::io_error));
  }
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return parse(text);
}

void IPFilter::add(IPRange range) {
  ranges_.push_back(std::move(range));
  std::sort(ranges_.begin(), ranges_.end(), [](const IPRange& lhs, const IPRange& rhs) {
    if (lhs.start.host() != rhs.start.host()) {
      return lhs.start.host() < rhs.start.host();
    }
    return lhs.end.host() < rhs.end.host();
  });
  rebuild_index();
}

void IPFilter::rebuild_index() {
  max_end_prefix_.clear();
  max_end_prefix_.reserve(ranges_.size());
  std::uint32_t max_end = 0;
  for (const auto& range : ranges_) {
    max_end = std::max(max_end, range.end.host());
    max_end_prefix_.push_back(max_end);
  }
}

bool IPFilter::blocked(IPv4 ip, std::uint8_t threshold) const noexcept {
  const auto value = ip.host();
  const auto it = std::upper_bound(ranges_.begin(), ranges_.end(), value,
                                   [](std::uint32_t v, const IPRange& range) {
                                     return v < range.start.host();
                                   });
  auto index = static_cast<std::size_t>(std::distance(ranges_.begin(), it));
  while (index > 0) {
    --index;
    const auto& range = ranges_[index];
    if (range.contains(ip) && range.level > threshold) {
      return true;
    }
    if (index == 0 || max_end_prefix_[index - 1] < value) {
      break;
    }
  }
  return false;
}

} // namespace ed2k::infra
