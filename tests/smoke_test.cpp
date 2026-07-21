#include <gtest/gtest.h>
#include "ed2k/version.hpp"
TEST(Smoke, VersionNonEmpty) { EXPECT_FALSE(ed2k::version().empty()); }
TEST(Smoke, VersionMatchesRelease) { EXPECT_EQ(ed2k::version(), "2.5.2"); }
TEST(Smoke, CompileTimeVersionConstants) {
  static_assert(ed2k::version_major == 2);
  static_assert(ed2k::version_minor == 5);
  static_assert(ed2k::version_patch == 2);
  static_assert(ED2K_VERSION_AT_LEAST(2, 5, 1));
  static_assert(ED2K_VERSION_AT_LEAST(2, 1, 0));
  static_assert(!ED2K_VERSION_AT_LEAST(2, 6, 0));
  static_assert(!ED2K_VERSION_AT_LEAST(3, 0, 0));
}
