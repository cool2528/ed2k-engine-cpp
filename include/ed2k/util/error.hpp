#pragma once
#include <system_error>
namespace ed2k {
enum class errc {
  ok = 0, buffer_underflow, bad_magic, unsupported_version,
  malformed_link, invalid_hex, invalid_base32, io_error,
  hash_mismatch, count_too_large,
  connect_failed, connection_closed, timed_out, packet_too_large, decompress_failed
};
std::error_code make_error_code(errc) noexcept;
}
template <> struct std::is_error_code_enum<ed2k::errc> : std::true_type {};
