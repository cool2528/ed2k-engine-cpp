#include "ed2k/infra/proxy.hpp"

#include <charconv>

#include "ed2k/util/error.hpp"

namespace ed2k::infra {
namespace {

tl::unexpected<std::error_code> bad_proxy_uri() {
  return tl::unexpected(make_error_code(errc::malformed_link));
}

tl::expected<std::uint16_t, std::error_code> parse_port(std::string_view text) {
  std::uint32_t port = 0;
  auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), port);
  if (ec != std::errc{} || ptr != text.data() + text.size() || port == 0 || port > 65535) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  return static_cast<std::uint16_t>(port);
}

tl::expected<ProxyConfig, std::error_code>
parse_with_prefix(std::string_view uri, std::string_view prefix, ProxyType type) {
  if (uri.substr(0, prefix.size()) != prefix) {
    return bad_proxy_uri();
  }
  auto rest = uri.substr(prefix.size());
  const auto colon = rest.rfind(':');
  if (colon == std::string_view::npos || colon == 0 || colon + 1 >= rest.size()) {
    return bad_proxy_uri();
  }
  auto port = parse_port(rest.substr(colon + 1));
  if (!port) {
    return tl::unexpected(port.error());
  }
  ProxyConfig config;
  config.type = type;
  config.host.assign(rest.substr(0, colon));
  config.port = *port;
  return config;
}

} // namespace

tl::expected<ProxyConfig, std::error_code> ProxyConfig::parse(std::string_view uri) {
  constexpr std::string_view socks_prefix = "socks5://";
  constexpr std::string_view http_prefix = "http://";
  if (uri.substr(0, socks_prefix.size()) == socks_prefix) {
    return parse_with_prefix(uri, socks_prefix, ProxyType::Socks5);
  }
  if (uri.substr(0, http_prefix.size()) == http_prefix) {
    return parse_with_prefix(uri, http_prefix, ProxyType::HttpConnect);
  }
  return bad_proxy_uri();
}

} // namespace ed2k::infra
