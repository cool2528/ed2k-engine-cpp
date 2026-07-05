#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "ed2k/kad/kad_id.hpp"

namespace ed2k::kad {

std::vector<std::string> keywords_for_name(std::string_view text, bool allow_duplicates = false);
KadID keyword_id(std::string_view keyword);

} // namespace ed2k::kad
