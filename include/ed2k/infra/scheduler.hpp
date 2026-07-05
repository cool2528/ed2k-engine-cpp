#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>
#include <vector>

#include <tl/expected.hpp>

namespace ed2k::infra {

struct BandwidthLimits {
  std::uint32_t upload_limit_bps = 0;
  std::uint32_t download_limit_bps = 0;
};

struct SchedulerRule {
  std::uint16_t start_minute = 0;
  std::uint16_t end_minute = 0;
  BandwidthLimits limits;

  bool active_at(int day, std::uint16_t minute_of_day) const noexcept;
  static tl::expected<SchedulerRule, std::error_code> parse(std::string_view text);
};

class Scheduler {
 public:
  void add(SchedulerRule rule);
  std::optional<BandwidthLimits> limits_at(int day, std::uint16_t minute_of_day) const;

 private:
  std::vector<SchedulerRule> rules_;
};

} // namespace ed2k::infra
