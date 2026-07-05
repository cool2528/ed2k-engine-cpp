#include <gtest/gtest.h>

#include <string>

#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/util/error.hpp"

using ed2k::IPv4;
using ed2k::infra::IPFilter;
using ed2k::infra::IPRange;

namespace {
IPv4 ip(const char* dotted) {
  return *IPv4::from_dotted(dotted);
}
} // namespace

TEST(IPFilter, ParsesRangeLinesAndAppliesStrictLevelThreshold) {
  auto parsed = IPFilter::parse(
      "1.2.3.0,1.2.3.255,128,bad range\n"
      "5.6.7.8,5.6.7.8,40,low level\n");
  ASSERT_TRUE(parsed.has_value()) << parsed.error().message();

  EXPECT_EQ(parsed->ranges().size(), 2u);
  EXPECT_TRUE(parsed->blocked(ip("1.2.3.4"), 127));
  EXPECT_FALSE(parsed->blocked(ip("1.2.3.4"), 128));
  EXPECT_FALSE(parsed->blocked(ip("5.6.7.8"), 127));
  EXPECT_FALSE(parsed->blocked(ip("9.9.9.9"), 127));
}

TEST(IPFilter, ParsesCidrLinesAndKeepsNames) {
  auto parsed = IPFilter::parse(
      "# comment\n"
      "10.20.0.0/16,200,corp block\n"
      "0.0.0.0/0,10,low priority\n");
  ASSERT_TRUE(parsed.has_value()) << parsed.error().message();

  EXPECT_TRUE(parsed->blocked(ip("10.20.30.40"), 199));
  EXPECT_FALSE(parsed->blocked(ip("10.21.0.1"), 199));
  EXPECT_FALSE(parsed->blocked(ip("8.8.8.8"), 10));
  EXPECT_TRUE(parsed->blocked(ip("8.8.8.8"), 9));

  const auto& ranges = parsed->ranges();
  ASSERT_EQ(ranges.size(), 2u);
  EXPECT_EQ(ranges[1].name, "corp block");
}

TEST(IPFilter, SortsRangesForLookupIndependentOfInputOrder) {
  IPFilter filter;
  for (int i = 250; i >= 1; --i) {
    const auto start = IPv4::from_host((10u << 24) | (static_cast<std::uint32_t>(i) << 16));
    const auto end = IPv4::from_host((10u << 24) | (static_cast<std::uint32_t>(i) << 16) | 0x0000ffffu);
    filter.add(IPRange{.start = start, .end = end, .level = 180, .name = "generated"});
  }

  ASSERT_EQ(filter.ranges().size(), 250u);
  EXPECT_LT(filter.ranges().front().start.host(), filter.ranges().back().start.host());
  EXPECT_TRUE(filter.blocked(ip("10.42.1.2"), 127));
  EXPECT_FALSE(filter.blocked(ip("10.251.0.1"), 127));
}

TEST(IPFilter, EarlierBroadRangeStillAppliesAfterLaterNarrowMiss) {
  auto parsed = IPFilter::parse(
      "0.0.0.0/0,200,all\n"
      "10.20.0.0/16,10,narrow allow\n");
  ASSERT_TRUE(parsed.has_value()) << parsed.error().message();

  EXPECT_TRUE(parsed->blocked(ip("10.21.0.1"), 127));
}

TEST(IPFilter, RejectsMalformedInput) {
  auto bad_ip = IPFilter::parse("1.2.3.999,1.2.3.255,128,bad\n");
  ASSERT_FALSE(bad_ip.has_value());
  EXPECT_EQ(bad_ip.error(), ed2k::make_error_code(ed2k::errc::malformed_link));

  auto bad_level = IPFilter::parse("1.2.3.0,1.2.3.255,999,bad\n");
  ASSERT_FALSE(bad_level.has_value());
  EXPECT_EQ(bad_level.error(), ed2k::make_error_code(ed2k::errc::malformed_link));

  auto reversed = IPFilter::parse("1.2.3.255,1.2.3.0,128,bad\n");
  ASSERT_FALSE(reversed.has_value());
  EXPECT_EQ(reversed.error(), ed2k::make_error_code(ed2k::errc::malformed_link));
}
