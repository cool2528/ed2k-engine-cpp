#include "ed2k/util/error.hpp"
namespace {
struct Ed2kCategory : std::error_category {
  const char* name() const noexcept override { return "ed2k"; }
  std::string message(int c) const override {
    using ed2k::errc;
    switch (static_cast<errc>(c)) {
      case errc::ok: return "ok";
      case errc::buffer_underflow: return "buffer underflow";
      case errc::bad_magic: return "bad magic byte";
      case errc::unsupported_version: return "unsupported version";
      case errc::malformed_link: return "malformed ed2k link";
      case errc::invalid_hex: return "invalid hex string";
      case errc::invalid_base32: return "invalid base32 string";
      case errc::io_error: return "io error";
      case errc::hash_mismatch: return "hash mismatch";
      case errc::count_too_large: return "count too large";
      case errc::connect_failed: return "connect failed";
      case errc::connection_closed: return "connection closed";
      case errc::timed_out: return "operation timed out";
      case errc::packet_too_large: return "packet too large";
      case errc::decompress_failed: return "decompress failed";
      case errc::login_rejected: return "login rejected";
      case errc::server_protocol_error: return "server protocol error";
      case errc::tls_error: return "TLS error";
      case errc::file_not_found: return "file not found";
      case errc::upload_queued: return "upload queued";
      case errc::block_corrupt: return "block corrupt";
      case errc::ip_filtered: return "ip filtered";
      case errc::cancelled: return "operation cancelled";
    }
    return "unknown ed2k error";
  }
};
const Ed2kCategory g_category;
}
namespace ed2k {
std::error_code make_error_code(errc e) noexcept { return {static_cast<int>(e), g_category}; }
}
