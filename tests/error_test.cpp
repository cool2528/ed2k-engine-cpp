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
TEST(Error, NetCodesHaveMessages){
  EXPECT_NE(ed2k::make_error_code(ed2k::errc::timed_out).message().find("timed out"), std::string::npos);
  EXPECT_NE(ed2k::make_error_code(ed2k::errc::packet_too_large).message().find("too large"), std::string::npos);
  EXPECT_NE(ed2k::make_error_code(ed2k::errc::connection_closed).message().find("closed"), std::string::npos);
  EXPECT_TRUE(ed2k::make_error_code(ed2k::errc::connect_failed));
  EXPECT_TRUE(ed2k::make_error_code(ed2k::errc::decompress_failed));
}
