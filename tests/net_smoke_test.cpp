#include <gtest/gtest.h>
#include <boost/asio.hpp>
TEST(NetSmoke, AsioContextRuns){
  boost::asio::io_context ctx;
  bool ran=false;
  boost::asio::post(ctx, [&]{ ran=true; });
  ctx.run();
  EXPECT_TRUE(ran);
}
