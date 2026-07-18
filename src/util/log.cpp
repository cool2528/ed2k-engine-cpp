#include "ed2k/util/log.hpp"
#include <mutex>
namespace ed2k {
namespace {
  log_handler g_handler;
  std::mutex g_handler_mutex;
}

void set_log_handler(log_handler handler) {
  std::lock_guard lk(g_handler_mutex);
  g_handler = std::move(handler);
}

void log_message(log_level level, std::string_view message) {
  std::lock_guard lk(g_handler_mutex);
  if (g_handler) g_handler(level, message);
}

}
