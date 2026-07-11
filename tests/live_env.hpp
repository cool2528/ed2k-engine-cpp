#pragma once
#include <charconv>
#include <cstdlib>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include "ed2k/app/server_session.hpp"
#include "ed2k/core/hash.hpp"
#include "ed2k/server/messages.hpp"
namespace ed2k::test {
inline bool live_enabled(){
  const char* v = std::getenv("ED2K_LIVE");
  return v && std::string(v) == "1";
}
inline bool live_obfuscation_enabled(){
  const char* v = std::getenv("ED2K_LIVE_OBFUSCATION");
  return live_enabled() && v && std::string(v) == "1";
}
inline std::optional<ed2k::app::ServerTarget> env_server(){
  const char* v = std::getenv("ED2K_SERVER");
  if(!v || !*v) return std::nullopt;
  std::string s = v;
  auto colon = s.rfind(':');
  if(colon == std::string::npos) return std::nullopt;
  auto ip = ed2k::IPv4::from_dotted(s.substr(0, colon));
  if(!ip) return std::nullopt;
  ed2k::app::ServerTarget t; t.ip = *ip; t.port = std::uint16_t(std::stoi(s.substr(colon + 1)));
  return t;
}
inline std::string env_link(){ const char* v = std::getenv("ED2K_LINK"); return v ? v : ""; }
inline std::string env_source(){ const char* v = std::getenv("ED2K_SOURCE"); return v ? v : ""; }
inline tl::expected<ed2k::server::SourceEndpoint, std::string>
parse_source_endpoint(std::string_view source){
  const auto colon = source.rfind(':');
  if(colon == std::string_view::npos || colon == 0 || colon + 1 == source.size()) {
    return tl::unexpected<std::string>{"ED2K_SOURCE must use ip:port syntax"};
  }
  const auto ip = ed2k::IPv4::from_dotted(source.substr(0, colon));
  if(!ip) {
    return tl::unexpected<std::string>{"ED2K_SOURCE must contain a valid IPv4 address"};
  }
  std::uint32_t port = 0;
  const auto port_text = source.substr(colon + 1);
  const auto parsed = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
  if(parsed.ec != std::errc{} || parsed.ptr != port_text.data() + port_text.size() ||
     port == 0 || port > 65535) {
    return tl::unexpected<std::string>{
      "ED2K_SOURCE port must be an integer between 1 and 65535"};
  }

  // SourceEndpoint ids use aMule little-endian byte order.
  const std::uint32_t host = ip->host();
  const std::uint32_t id = ((host & 0x000000FFu) << 24) |
                           ((host & 0x0000FF00u) << 8)  |
                           ((host & 0x00FF0000u) >> 8)  |
                           ((host & 0xFF000000u) >> 24);
  return ed2k::server::SourceEndpoint{id, static_cast<std::uint16_t>(port)};
}
inline std::string env_expect_md4(){ const char* v = std::getenv("ED2K_EXPECT_MD4"); return v ? v : ""; }
}
