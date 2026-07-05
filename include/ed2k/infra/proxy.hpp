#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

#include <tl/expected.hpp>

namespace ed2k::infra {

enum class ProxyType {
  Socks5,
  HttpConnect,
};

struct ProxyConfig {
  ProxyType type = ProxyType::Socks5;
  std::string host;
  std::uint16_t port = 0;

  static tl::expected<ProxyConfig, std::error_code> parse(std::string_view uri);
};

} // namespace ed2k::infra
