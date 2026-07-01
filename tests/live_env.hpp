#pragma once
#include <cstdlib>
#include <optional>
#include <string>
#include "ed2k/app/server_session.hpp"
#include "ed2k/core/hash.hpp"
namespace ed2k::test {
inline bool live_enabled(){
  const char* v = std::getenv("ED2K_LIVE");
  return v && std::string(v) == "1";
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
inline std::string env_expect_md4(){ const char* v = std::getenv("ED2K_EXPECT_MD4"); return v ? v : ""; }
}
