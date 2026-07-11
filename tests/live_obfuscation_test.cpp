#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <limits>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>

#include "ed2k/download/part_file.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/util/error.hpp"
#include "live_env.hpp"

using namespace ed2k;
using namespace std::chrono_literals;

namespace {
struct LiveFixture {
  Ed2kFileLink link;
  server::SourceEndpoint source;
  UserHash amule_hash;
  FileHash expected_hash;
  ed2k::test::AmuleObfuscationMode mode;
};

tl::expected<LiveFixture, std::string> live_fixture() {
  auto amule_hash = ed2k::test::env_amule_user_hash();
  if(!amule_hash) return tl::unexpected(amule_hash.error());
  auto mode = ed2k::test::env_amule_obfuscation_mode();
  if(!mode) return tl::unexpected(mode.error());
  const auto source_text = ed2k::test::env_source();
  if(source_text.empty()) {
    return tl::unexpected<std::string>{"set ED2K_SOURCE=ip:port for the managed aMule peer"};
  }
  auto source = ed2k::test::parse_source_endpoint(source_text);
  if(!source) return tl::unexpected(source.error());
  if(source->low_id()) {
    return tl::unexpected<std::string>{"ED2K_SOURCE must identify a reachable HighID peer"};
  }
  const auto link_text = ed2k::test::env_link();
  if(link_text.empty()) {
    return tl::unexpected<std::string>{"set ED2K_LINK to the managed fixture eD2k link"};
  }
  auto parsed_link = parse_link(link_text);
  if(!parsed_link) return tl::unexpected<std::string>{"ED2K_LINK must be a valid eD2k link"};
  auto* link = std::get_if<Ed2kFileLink>(&*parsed_link);
  if(!link) return tl::unexpected<std::string>{"ED2K_LINK must be an eD2k file link"};
  const auto expected_text = ed2k::test::env_expect_md4();
  if(expected_text.empty()) {
    return tl::unexpected<std::string>{"set ED2K_EXPECT_MD4 to the fixture's 32-hex Red eD2k hash"};
  }
  auto expected_hash = FileHash::from_hex(expected_text);
  if(!expected_hash) {
    return tl::unexpected<std::string>{"ED2K_EXPECT_MD4 must be exactly 32 hexadecimal characters"};
  }
  if(link->hash != *expected_hash) {
    return tl::unexpected<std::string>{"ED2K_LINK hash must equal ED2K_EXPECT_MD4"};
  }
  return LiveFixture{*link, *source, *amule_hash, *expected_hash, *mode};
}

peer::HelloInfo live_obfuscation_hello(peer::ObfuscationPolicy policy) {
  peer::HelloInfo hello;
  hello.nickname = "ed2k-live-obfuscation";
  hello.version = 0x3c;
  hello.port = 4662;
  hello.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
  hello.supports_obfuscation = policy != peer::ObfuscationPolicy::disabled;
  hello.requests_obfuscation = policy != peer::ObfuscationPolicy::disabled;
  hello.requires_obfuscation = policy == peer::ObfuscationPolicy::required;
  return hello;
}

boost::asio::awaitable<tl::expected<void, std::error_code>>
download_fixture(peer::C2CConnection& connection, const Ed2kFileLink& link,
                 const std::filesystem::path& out) {
  if(link.size > std::numeric_limits<std::uint32_t>::max()) {
    co_return tl::unexpected(make_error_code(errc::unsupported_version));
  }
  auto status = co_await connection.request_file(link.hash, 15s);
  if(!status) co_return tl::unexpected(status.error());
  std::vector<PartHash> part_hashes;
  if(link.size > PART_SIZE) {
    auto hashes = co_await connection.request_hashset(link.hash, 15s);
    if(!hashes) co_return tl::unexpected(hashes.error());
    part_hashes = std::move(*hashes);
  }
  download::PartFile part_file(out, link.size, link.hash, std::move(part_hashes));
  (void)co_await connection.request_filename(link.hash, 15s);
  auto upload = co_await connection.start_upload(link.hash, 15s);
  if(!upload) co_return tl::unexpected(upload.error());

  const auto part_count = static_cast<std::size_t>((link.size + PART_SIZE - 1) / PART_SIZE);
  auto peer_parts = std::move(status->parts);
  if(peer_parts.empty()) peer_parts.assign(part_count, true);
  for(std::size_t part = 0; part < part_count; ++part) {
    if(part >= peer_parts.size() || !peer_parts[part]) continue;
    const auto part_start = static_cast<std::uint64_t>(part) * PART_SIZE;
    const auto part_end = std::min(part_start + PART_SIZE, link.size);
    for(auto start = part_start; start < part_end; start += AICH_BLOCK_SIZE) {
      const auto block = static_cast<std::size_t>((start - part_start) / AICH_BLOCK_SIZE);
      if(part_file.is_block_done(part, block)) continue;
      const auto end = std::min(start + AICH_BLOCK_SIZE, part_end);
      auto blocks = co_await connection.request_blocks(
        link.hash,
        std::array<std::uint32_t, 3>{static_cast<std::uint32_t>(start), 0, 0},
        std::array<std::uint32_t, 3>{static_cast<std::uint32_t>(end), 0, 0}, 30s);
      if(!blocks) co_return tl::unexpected(blocks.error());
      if(blocks->empty()) co_return tl::unexpected(make_error_code(errc::io_error));
      for(const auto& received : *blocks) {
        auto written = part_file.write_block(
          received.start, received.end, std::span<const std::byte>(received.data));
        if(!written) co_return tl::unexpected(written.error());
      }
    }
  }
  if(!part_file.complete()) co_return tl::unexpected(make_error_code(errc::io_error));
  co_return tl::expected<void, std::error_code>{};
}

template <class F> void run_coro(ed2k::net::IoRuntime& runtime, F&& body) {
  bool done = false;
  boost::asio::co_spawn(runtime.context(),
    [&]() -> boost::asio::awaitable<void> { co_await body(); done = true; co_return; },
    [&](std::exception_ptr error) {
      runtime.stop();
      if(error) std::rethrow_exception(error);
    });
  runtime.run();
  runtime.restart();
  EXPECT_TRUE(done);
}

void verify_download(const std::filesystem::path& out, const Ed2kFileLink& link,
                     const FileHash& expected) {
  ASSERT_TRUE(std::filesystem::exists(out)) << "encrypted download did not produce the fixture";
  ASSERT_EQ(std::filesystem::file_size(out), link.size);
  auto hash = hash_file(out.string(), HashVariant::Red);
  ASSERT_TRUE(hash.has_value()) << (hash ? "" : hash.error().message());
  EXPECT_EQ(hash->file_hash, link.hash);
  EXPECT_EQ(hash->file_hash, expected);
}
}

TEST(LiveObfuscation, ConfigurationUserHashParserIsStrict) {
  auto valid = ed2k::test::parse_user_hash("00112233445566778899aabbccddeeff");
  ASSERT_TRUE(valid.has_value());
  EXPECT_EQ(valid->to_hex(), "00112233445566778899aabbccddeeff");
  EXPECT_FALSE(ed2k::test::parse_user_hash("00112233445566778899aabbccddee").has_value());
  EXPECT_FALSE(ed2k::test::parse_user_hash("00112233445566778899aabbccddeeff00").has_value());
  EXPECT_FALSE(ed2k::test::parse_user_hash("00112233445566778899aabbccddeefg").has_value());
}

// Configuration gates only. Encrypted peer transfer is covered by Task 3.
TEST(LiveObfuscation, ConfigurationLinkIsValid) {
  if(!ed2k::test::live_obfuscation_enabled()) {
    GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_LIVE_OBFUSCATION=1";
  }

  const auto link_s = ed2k::test::env_link();
  ASSERT_FALSE(link_s.empty())
    << "set ED2K_LINK=ed2k://|file|...|size|hash|/ for the configured file fixture";
  const auto parsed = parse_link(link_s);
  ASSERT_TRUE(parsed.has_value()) << "ED2K_LINK must be a valid eD2k link";
  ASSERT_NE(std::get_if<Ed2kFileLink>(&*parsed), nullptr)
    << "ED2K_LINK must be an eD2k file link";
}

TEST(LiveObfuscation, ConfigurationSourceIsValidHighId) {
  if(!ed2k::test::live_obfuscation_enabled()) {
    GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_LIVE_OBFUSCATION=1";
  }

  const auto source_s = ed2k::test::env_source();
  ASSERT_FALSE(source_s.empty())
    << "set ED2K_SOURCE=ip:port for the configured peer endpoint";
  const auto source = ed2k::test::parse_source_endpoint(source_s);
  ASSERT_TRUE(source.has_value()) << source.error();
  ASSERT_FALSE(source->low_id())
    << "ED2K_SOURCE address must classify as HighID";
}

TEST(LiveObfuscation, RequiredPeerCompletesEncryptedDownload) {
  if(!ed2k::test::live_obfuscation_enabled()) {
    GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_LIVE_OBFUSCATION=1";
  }
  auto fixture = live_fixture();
  ASSERT_TRUE(fixture.has_value()) << fixture.error();
  if(fixture->mode != ed2k::test::AmuleObfuscationMode::required) {
    GTEST_SKIP() << "requires ED2K_AMULE_OBFUSCATION_MODE=required";
  }

  const auto out = std::filesystem::temp_directory_path() /
                   "ed2k_live_obfuscation_required.part";
  std::filesystem::remove(out);
  std::filesystem::remove(out.string() + ".met");
  ed2k::net::IoRuntime runtime;
  run_coro(runtime, [&]() -> boost::asio::awaitable<void> {
    peer::C2CConnection connection(runtime.executor());
    auto connected = co_await connection.connect(
      peer::PeerIdentity{fixture->source, fixture->amule_hash},
      peer::ObfuscationPolicy::required, 15s);
    EXPECT_TRUE(connected.has_value()) << (connected ? "" : connected.error().message());
    if(!connected) co_return;
    EXPECT_TRUE(connection.encrypted());
    if(!connection.encrypted()) co_return;
    RecordProperty("transport", "encrypted");
    std::printf("  transport=encrypted\n");
    auto hello = co_await connection.handshake(
      live_obfuscation_hello(peer::ObfuscationPolicy::required), 15s);
    EXPECT_TRUE(hello.has_value()) << (hello ? "" : hello.error().message());
    if(!hello) co_return;
    auto downloaded = co_await download_fixture(connection, fixture->link, out);
    EXPECT_TRUE(downloaded.has_value())
      << (downloaded ? "" : downloaded.error().message());
    co_return;
  });
  verify_download(out, fixture->link, fixture->expected_hash);
  std::filesystem::remove(out);
  std::filesystem::remove(out.string() + ".met");
}

TEST(LiveObfuscation, RequiredPeerRejectsPlainHandshake) {
  if(!ed2k::test::live_obfuscation_enabled()) {
    GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_LIVE_OBFUSCATION=1";
  }
  auto fixture = live_fixture();
  ASSERT_TRUE(fixture.has_value()) << fixture.error();
  if(fixture->mode != ed2k::test::AmuleObfuscationMode::required) {
    GTEST_SKIP() << "requires ED2K_AMULE_OBFUSCATION_MODE=required";
  }

  ed2k::net::IoRuntime runtime;
  run_coro(runtime, [&]() -> boost::asio::awaitable<void> {
    peer::C2CConnection connection(runtime.executor());
    auto connected = co_await connection.connect(
      IPv4::from_wire(fixture->source.id), fixture->source.port, 15s);
    EXPECT_TRUE(connected.has_value()) << (connected ? "" : connected.error().message());
    if(!connected) co_return;
    EXPECT_FALSE(connection.encrypted());
    if(connection.encrypted()) co_return;
    RecordProperty("transport", "plain-rejected");
    std::printf("  transport=plain expected=rejected\n");
    auto hello = co_await connection.handshake(
      live_obfuscation_hello(peer::ObfuscationPolicy::disabled), 5s);
    EXPECT_FALSE(hello.has_value())
      << "required-mode aMule accepted a plaintext HELLO";
    if(!hello) {
      EXPECT_EQ(hello.error(), make_error_code(errc::connection_closed))
        << "required-mode rejection must actively close the plaintext session, not time out";
    }
    co_return;
  });
}

TEST(LiveObfuscation, OptionalPeerAllowsConfiguredPlainFallback) {
  if(!ed2k::test::live_obfuscation_enabled()) {
    GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_LIVE_OBFUSCATION=1";
  }
  auto fixture = live_fixture();
  ASSERT_TRUE(fixture.has_value()) << fixture.error();
  if(fixture->mode != ed2k::test::AmuleObfuscationMode::optional) {
    GTEST_SKIP() << "requires ED2K_AMULE_OBFUSCATION_MODE=optional";
  }

  auto wrong_hash = *UserHash::from_hex("ffffffffffffffffffffffffffffffff");
  if(wrong_hash == fixture->amule_hash) {
    wrong_hash = *UserHash::from_hex("00000000000000000000000000000000");
  }
  ed2k::net::IoRuntime runtime;
  run_coro(runtime, [&]() -> boost::asio::awaitable<void> {
    peer::C2CConnection connection(runtime.executor());
    auto connected = co_await connection.connect(
      peer::PeerIdentity{fixture->source, wrong_hash},
      peer::ObfuscationPolicy::preferred, 15s);
    EXPECT_TRUE(connected.has_value()) << (connected ? "" : connected.error().message());
    if(!connected) co_return;
    EXPECT_FALSE(connection.encrypted())
      << "wrong remote hash must force the configured plaintext fallback";
    if(connection.encrypted()) co_return;
    RecordProperty("transport", "plain-fallback");
    std::printf("  transport=plain reason=configured-fallback\n");
    auto hello = co_await connection.handshake(
      live_obfuscation_hello(peer::ObfuscationPolicy::preferred), 15s);
    EXPECT_TRUE(hello.has_value())
      << (hello ? "" : hello.error().message())
      << "; optional-mode aMule must accept the fallback plaintext HELLO";
    co_return;
  });
}
