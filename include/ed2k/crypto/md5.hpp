#pragma once

#include <array>
#include <cstddef>
#include <span>

namespace ed2k::crypto {

using MD5Digest = std::array<std::byte, 16>;

MD5Digest md5(std::span<const std::byte> data);

} // namespace ed2k::crypto
