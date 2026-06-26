#include <gtest/gtest.h>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include "ed2k/net/runtime.hpp"
using namespace ed2k::net;
static boost::asio::awaitable<void> set_flag(bool& f){ f = true; co_return; }
TEST(IoRuntime, RunsSpawnedCoroutine){
  IoRuntime rt; bool flag=false;
  rt.co_spawn_detached(set_flag(flag));
  rt.run();
  EXPECT_TRUE(flag);
}
