#pragma once
#include <functional>
#include <string_view>
namespace ed2k {

enum class log_level { trace, debug, info, warn, error, critical };

using log_handler = std::function<void(log_level, std::string_view)>;

void set_log_handler(log_handler handler);
void log_message(log_level level, std::string_view message);

}
