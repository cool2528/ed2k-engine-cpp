#include <gtest/gtest.h>
#include "ed2k/version.hpp"
TEST(Smoke, VersionNonEmpty) { EXPECT_FALSE(ed2k::version().empty()); }
TEST(Smoke, VersionMatchesRelease) { EXPECT_EQ(ed2k::version(), "2.2.0"); }
