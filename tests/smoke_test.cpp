#include <gtest/gtest.h>
#include "ed2k/version.hpp"
TEST(Smoke, VersionNonEmpty) { EXPECT_FALSE(ed2k::version().empty()); }
