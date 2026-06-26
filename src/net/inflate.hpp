#pragma once
#include <cstddef>
#include <span>
#include <vector>
#include <system_error>
#include <tl/expected.hpp>
namespace ed2k::net {
// zlib(RFC 1950) 解压；输出累计 > max_out → errc::decompress_failed；坏流 → errc::decompress_failed
tl::expected<std::vector<std::byte>,std::error_code>
zlib_inflate(std::span<const std::byte> in, std::size_t max_out);
}
