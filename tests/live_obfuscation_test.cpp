#include <gtest/gtest.h>

#include "ed2k/link/ed2k_link.hpp"
#include "live_env.hpp"

using namespace ed2k;

// Configuration gates only. Encrypted peer transfer is covered by Task 3.
TEST(LiveObfuscation, ConfigurationLinkIsValid) {
  if(!ed2k::test::live_obfuscation_enabled()) {
    GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_LIVE_OBFUSCATION=1";
  }

  const auto link_s = ed2k::test::env_link();
  ASSERT_FALSE(link_s.empty())
    << "set ED2K_LINK=ed2k://|file|...|size|hash|/ for the configured file fixture";
  const auto parsed = parse_link(link_s);
  ASSERT_TRUE(parsed.has_value()) << "ED2K_LINK must be a valid eD2k link";
  ASSERT_NE(std::get_if<Ed2kFileLink>(&*parsed), nullptr)
    << "ED2K_LINK must be an eD2k file link";
}

TEST(LiveObfuscation, ConfigurationSourceIsValidHighId) {
  if(!ed2k::test::live_obfuscation_enabled()) {
    GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_LIVE_OBFUSCATION=1";
  }

  const auto source_s = ed2k::test::env_source();
  ASSERT_FALSE(source_s.empty())
    << "set ED2K_SOURCE=ip:port for the configured peer endpoint";
  const auto source = ed2k::test::parse_source_endpoint(source_s);
  ASSERT_TRUE(source.has_value()) << source.error();
  ASSERT_FALSE(source->low_id())
    << "ED2K_SOURCE address must classify as HighID";
}
