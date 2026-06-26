#include "ed2k/util/log.hpp"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <memory>
namespace ed2k {
spdlog::logger& log(){
  static std::shared_ptr<spdlog::logger> lg = []{
    auto l = spdlog::stderr_color_mt("ed2k");
    l->set_level(spdlog::level::info);
    return l;
  }();
  return *lg;
}
}
