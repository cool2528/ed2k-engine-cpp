#include "ed2k/infra/scheduler.hpp"

#include <charconv>
#include <sstream>
#include <string>

#include "ed2k/util/error.hpp"

namespace ed2k::infra {
namespace {

tl::unexpected<std::error_code> bad_rule() {
  return tl::unexpected(make_error_code(errc::malformed_link));
}

tl::expected<std::uint32_t, std::error_code> parse_u32(std::string_view text) {
  std::uint32_t value = 0;
  auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (ec != std::errc{} || ptr != text.data() + text.size()) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  return value;
}

tl::expected<std::uint16_t, std::error_code> parse_time(std::string_view text) {
  if (text.size() != 5 || text[2] != ':') {
    return bad_rule();
  }
  auto hour = parse_u32(text.substr(0, 2));
  auto minute = parse_u32(text.substr(3, 2));
  if (!hour || !minute || *hour > 24 || *minute > 59 || (*hour == 24 && *minute != 0)) {
    return bad_rule();
  }
  return static_cast<std::uint16_t>((*hour * 60u) + *minute);
}

tl::expected<void, std::error_code>
parse_limit_token(std::string_view token, BandwidthLimits& limits, bool& saw_limit) {
  constexpr std::string_view upload = "upload=";
  constexpr std::string_view download = "download=";
  if (token.substr(0, upload.size()) == upload) {
    auto value = parse_u32(token.substr(upload.size()));
    if (!value) {
      return tl::unexpected(value.error());
    }
    limits.upload_limit_bps = *value;
    saw_limit = true;
    return {};
  }
  if (token.substr(0, download.size()) == download) {
    auto value = parse_u32(token.substr(download.size()));
    if (!value) {
      return tl::unexpected(value.error());
    }
    limits.download_limit_bps = *value;
    saw_limit = true;
    return {};
  }
  return bad_rule();
}

} // namespace

bool SchedulerRule::active_at(int day, std::uint16_t minute_of_day) const noexcept {
  (void)day;
  return minute_of_day >= start_minute && minute_of_day < end_minute;
}

tl::expected<SchedulerRule, std::error_code> SchedulerRule::parse(std::string_view text) {
  std::istringstream in{std::string(text)};
  std::string scope;
  std::string window;
  if (!(in >> scope >> window) || scope != "daily") {
    return bad_rule();
  }

  const auto dash = window.find('-');
  if (dash == std::string::npos) {
    return bad_rule();
  }
  auto start = parse_time(std::string_view(window).substr(0, dash));
  auto end = parse_time(std::string_view(window).substr(dash + 1));
  if (!start || !end || *start >= *end) {
    return bad_rule();
  }

  SchedulerRule rule;
  rule.start_minute = *start;
  rule.end_minute = *end;
  bool saw_limit = false;
  std::string token;
  while (in >> token) {
    auto parsed = parse_limit_token(token, rule.limits, saw_limit);
    if (!parsed) {
      return tl::unexpected(parsed.error());
    }
  }
  if (!saw_limit) {
    return bad_rule();
  }
  return rule;
}

void Scheduler::add(SchedulerRule rule) {
  rules_.push_back(rule);
}

std::optional<BandwidthLimits> Scheduler::limits_at(int day, std::uint16_t minute_of_day) const {
  for (const auto& rule : rules_) {
    if (rule.active_at(day, minute_of_day)) {
      return rule.limits;
    }
  }
  return std::nullopt;
}

} // namespace ed2k::infra
