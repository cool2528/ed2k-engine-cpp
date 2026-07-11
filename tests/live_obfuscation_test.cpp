#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include "ed2k/core/hash.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/server/messages.hpp"
#include "live_env.hpp"

using namespace ed2k;

TEST(LiveObfuscation, LinkFixtureIsValid) {
  if(!ed2k::test::live_obfuscation_enabled()) {
    GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_LIVE_OBFUSCATION=1";
  }

  const auto link_s = ed2k::test::env_link();
  ASSERT_FALSE(link_s.empty())
    << "set ED2K_LINK=ed2k://|file|...|size|hash|/ for the live obfuscation fixture";
  const auto parsed = parse_link(link_s);
  ASSERT_TRUE(parsed.has_value()) << "ED2K_LINK must be a valid eD2k link";
  ASSERT_NE(std::get_if<Ed2kFileLink>(&*parsed), nullptr)
    << "ED2K_LINK must be an eD2k file link";
}

TEST(LiveObfuscation, SourceFixtureIsValidHighId) {
  if(!ed2k::test::live_obfuscation_enabled()) {
    GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_LIVE_OBFUSCATION=1";
  }

  const auto source_s = ed2k::test::env_source();
  ASSERT_FALSE(source_s.empty())
    << "set ED2K_SOURCE=ip:port for a reachable HighID peer supporting obfuscation";
  const auto colon = source_s.rfind(':');
  ASSERT_NE(colon, std::string::npos) << "ED2K_SOURCE must be ip:port";
  const auto ip = IPv4::from_dotted(source_s.substr(0, colon));
  ASSERT_TRUE(ip.has_value()) << "ED2K_SOURCE must contain a valid IPv4 address";

  std::size_t consumed = 0;
  unsigned long parsed_port = 0;
  ASSERT_NO_THROW(parsed_port = std::stoul(source_s.substr(colon + 1), &consumed))
    << "ED2K_SOURCE port must be numeric";
  ASSERT_EQ(consumed, source_s.size() - colon - 1)
    << "ED2K_SOURCE port must be numeric";
  ASSERT_GE(parsed_port, 1ul) << "ED2K_SOURCE port must be between 1 and 65535";
  ASSERT_LE(parsed_port, 65535ul) << "ED2K_SOURCE port must be between 1 and 65535";

  // SourceEndpoint ids use aMule little-endian byte order, matching the
  // direct-peer conversion exercised by LiveDownload.LocalPeerCompletes.
  const std::uint32_t host = ip->host();
  const std::uint32_t id = ((host & 0x000000FFu) << 24) |
                           ((host & 0x0000FF00u) << 8)  |
                           ((host & 0x00FF0000u) >> 8)  |
                           ((host & 0xFF000000u) >> 24);
  const ed2k::server::SourceEndpoint source{
    id, static_cast<std::uint16_t>(parsed_port)};
  ASSERT_FALSE(source.low_id())
    << "ED2K_SOURCE must be a reachable HighID peer";
}
