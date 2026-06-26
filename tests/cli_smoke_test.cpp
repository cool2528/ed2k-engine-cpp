#include <gtest/gtest.h>
#include "ed2k/util/log.hpp"
TEST(CliLog, LoggerAvailable){
  auto& lg = ed2k::log();
  lg.info("cli smoke");
  SUCCEED();
}
