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
TEST(Error, ServerCodesHaveMessages){
  EXPECT_NE(ed2k::make_error_code(ed2k::errc::login_rejected).message().find("login rejected"), std::string::npos);
  EXPECT_NE(ed2k::make_error_code(ed2k::errc::server_protocol_error).message().find("protocol error"), std::string::npos);
  EXPECT_NE(ed2k::make_error_code(ed2k::errc::tls_error).message().find("TLS"), std::string::npos);
  EXPECT_TRUE(ed2k::make_error_code(ed2k::errc::login_rejected));
  EXPECT_TRUE(ed2k::make_error_code(ed2k::errc::server_protocol_error));
  EXPECT_TRUE(ed2k::make_error_code(ed2k::errc::tls_error));
}
TEST(Error, DownloadCodesHaveMessages){
  EXPECT_NE(ed2k::make_error_code(ed2k::errc::file_not_found).message().find("not found"), std::string::npos);
  EXPECT_NE(ed2k::make_error_code(ed2k::errc::upload_queued).message().find("queued"), std::string::npos);
  EXPECT_NE(ed2k::make_error_code(ed2k::errc::block_corrupt).message().find("corrupt"), std::string::npos);
  EXPECT_TRUE(ed2k::make_error_code(ed2k::errc::file_not_found));
  EXPECT_TRUE(ed2k::make_error_code(ed2k::errc::upload_queued));
  EXPECT_TRUE(ed2k::make_error_code(ed2k::errc::block_corrupt));
}

TEST(Error, LegacyNumericCodesRemainStable) {
  EXPECT_EQ(static_cast<int>(ed2k::errc::file_not_found), 17);
  EXPECT_EQ(static_cast<int>(ed2k::errc::upload_queued), 18);
  EXPECT_EQ(static_cast<int>(ed2k::errc::block_corrupt), 19);
  EXPECT_EQ(static_cast<int>(ed2k::errc::ip_filtered), 20);
  EXPECT_EQ(static_cast<int>(ed2k::errc::tls_error), 21);
}

TEST(Error, CancelledHasMessage){
  auto ec = ed2k::make_error_code(ed2k::errc::cancelled);
  EXPECT_TRUE(ec);
  EXPECT_EQ(ec.message(), "operation cancelled");
}
