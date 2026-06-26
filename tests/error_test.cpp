#include <gtest/gtest.h>
#include "ed2k/util/error.hpp"
TEST(Error, MakesCodeWithCategoryAndMessage) {
  std::error_code ec = ed2k::make_error_code(ed2k::errc::bad_magic);
  EXPECT_TRUE(ec);
  EXPECT_EQ(ec.value(), static_cast<int>(ed2k::errc::bad_magic));
  EXPECT_NE(ec.message().find("magic"), std::string::npos);
  EXPECT_STREQ(ec.category().name(), "ed2k");
}
TEST(Error, OkIsFalsy) {
  EXPECT_FALSE(ed2k::make_error_code(ed2k::errc::ok));
}
