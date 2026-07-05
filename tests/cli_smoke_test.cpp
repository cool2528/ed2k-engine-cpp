#include <gtest/gtest.h>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#ifndef _WIN32
#  include <sys/wait.h>
#endif
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/kad/nodes_dat.hpp"
#include "ed2k/infra/preferences.hpp"
#include "ed2k/infra/statistics.hpp"
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/server/opcodes.hpp"
#include "ed2k/util/log.hpp"
#include "mock_peer.hpp"
#include "mock_server.hpp"

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace {
std::optional<std::filesystem::path> find_tool() {
#ifdef _WIN32
  constexpr const char* exe = "ed2k-tool.exe";
#else
  constexpr const char* exe = "ed2k-tool";
#endif
  const auto cwd = std::filesystem::current_path();
  const std::filesystem::path candidates[] = {
      cwd / exe,
      cwd / "Debug" / exe,
      cwd / "Release" / exe,
      cwd / "build" / "default" / "Debug" / exe,
      cwd / "build" / "default" / "Release" / exe,
      cwd.parent_path() / exe,
      cwd.parent_path() / "Debug" / exe,
      cwd.parent_path() / "Release" / exe,
  };
  for (const auto& candidate : candidates) {
    if (std::filesystem::exists(candidate)) {
      return candidate;
    }
  }
  return std::nullopt;
}

int shell_exit_code(int rc) {
#ifdef _WIN32
  return rc;
#else
  if (WIFEXITED(rc)) {
    return WEXITSTATUS(rc);
  }
  return rc;
#endif
}

std::string shell_path(const std::filesystem::path& path) {
  return path.generic_string();
}

std::string shell_arg(std::string value) {
#ifdef _WIN32
  return "\"" + value + "\"";
#else
  return "'" + value + "'";
#endif
}

std::string quiet_redirect() {
#ifdef _WIN32
  return " > NUL";
#else
  return " > /dev/null";
#endif
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_bytes(const std::filesystem::path& path, std::span<const std::byte> bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

std::vector<std::byte> idchange_payload(std::uint32_t id, std::uint32_t flags) {
  ed2k::codec::ByteWriter w;
  w.u32(id);
  w.u32(flags);
  return w.take();
}

asio::awaitable<bool> read_ed2k_frame(tcp::socket& s) {
  std::array<std::byte, 5> hdr{};
  auto [h_ec, h_n] = co_await asio::async_read(s, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
  (void)h_n;
  if (h_ec) co_return false;
  auto header = ed2k::net::parse_header(hdr);
  if (!header) co_return false;
  std::vector<std::byte> body(header->size);
  auto [b_ec, b_n] = co_await asio::async_read(s, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
  (void)b_n;
  co_return !b_ec;
}
} // namespace

TEST(CliLog, LoggerAvailable){
  auto& lg = ed2k::log();
  lg.info("cli smoke");
  SUCCEED();
}

TEST(CliKad, BootstrapAcceptsNodesDatFile) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  const auto path = std::filesystem::temp_directory_path() / "ed2k_cli_kad_nodes.dat";
  const auto bytes = ed2k::kad::write_nodes_dat({});
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }

#ifdef _WIN32
  const std::string redirect = " > NUL";
#else
  const std::string redirect = " > /dev/null";
#endif
  const auto command = shell_path(*tool) + " kad-bootstrap " + shell_path(path) + redirect;
  EXPECT_EQ(shell_exit_code(std::system(command.c_str())), 0);
  std::filesystem::remove(path);
}

TEST(CliIPFilter, BlockCheckAcceptsIpfilterDat) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  const auto path = std::filesystem::temp_directory_path() / "ed2k_cli_ipfilter.dat";
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << "1.2.3.0,1.2.3.255,128,bad range\n";
  }

#ifdef _WIN32
  const std::string redirect = " > NUL";
#else
  const std::string redirect = " > /dev/null";
#endif
  const auto command = shell_path(*tool) + " ipfilter " + shell_path(path) +
                       " --block-check:1.2.3.4 --level:127" + redirect;
  EXPECT_EQ(shell_exit_code(std::system(command.c_str())), 0);
  std::filesystem::remove(path);
}

TEST(CliConfig, SetWritesPreferencesFile) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  const auto path = std::filesystem::temp_directory_path() / "ed2k_cli_preferences.dat";
  std::filesystem::remove(path);

#ifdef _WIN32
  const std::string redirect = " > NUL";
#else
  const std::string redirect = " > /dev/null";
#endif
  const auto command = shell_path(*tool) + " config " + shell_path(path) +
                       " --set:tcp_port=5555 --set:nickname=cli" + redirect;
  EXPECT_EQ(shell_exit_code(std::system(command.c_str())), 0);

  auto loaded = ed2k::infra::Preferences::load(path);
  ASSERT_TRUE(loaded.has_value()) << loaded.error().message();
  EXPECT_EQ(loaded->tcp_port, 5555);
  EXPECT_EQ(loaded->nickname, "cli");
  std::filesystem::remove(path);
}

TEST(CliConfig, GlobalConfigOptionSuppliesPreferencesPath) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  const auto path = std::filesystem::temp_directory_path() / "ed2k_cli_global_preferences.dat";
  std::filesystem::remove(path);

  const auto command = shell_path(*tool) + " --config " + shell_path(path) +
                       " config --set:nickname=global --set:tcp_port=5556" + quiet_redirect();
  EXPECT_EQ(shell_exit_code(std::system(command.c_str())), 0);

  auto loaded = ed2k::infra::Preferences::load(path);
  ASSERT_TRUE(loaded.has_value()) << loaded.error().message();
  EXPECT_EQ(loaded->nickname, "global");
  EXPECT_EQ(loaded->tcp_port, 5556);
  std::filesystem::remove(path);
}

TEST(CliIPFilter, GlobalIpfilterOptionSuppliesFilterPath) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  const auto path = std::filesystem::temp_directory_path() / "ed2k_cli_global_ipfilter.dat";
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << "2.3.4.0,2.3.4.255,128,bad range\n";
  }

  const auto command = shell_path(*tool) + " --ipfilter " + shell_path(path) +
                       " ipfilter --block-check:2.3.4.5 --level:127" + quiet_redirect();
  EXPECT_EQ(shell_exit_code(std::system(command.c_str())), 0);
  std::filesystem::remove(path);
}

TEST(CliCollection, CreateAndListRoundTrip) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  const auto path = std::filesystem::temp_directory_path() / "ed2k_cli_collection.emulecollection";
  std::filesystem::remove(path);
  const std::string link = "ed2k://|file|one.bin|123|00112233445566778899aabbccddeeff|/";

  auto create = shell_path(*tool) + " collection create " + shell_path(path) + " " +
                shell_arg(link) + quiet_redirect();
  EXPECT_EQ(shell_exit_code(std::system(create.c_str())), 0);

  auto list = shell_path(*tool) + " collection list " + shell_path(path) + quiet_redirect();
  EXPECT_EQ(shell_exit_code(std::system(list.c_str())), 0);
  EXPECT_NE(read_text(path).find(link), std::string::npos);
  std::filesystem::remove(path);
}

TEST(CliSchedule, AddAndListRule) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  const auto path = std::filesystem::temp_directory_path() / "ed2k_cli_schedule.txt";
  std::filesystem::remove(path);
  const std::string rule = "daily 08:00-18:00 upload=1024 download=2048";

  auto add = shell_path(*tool) + " schedule add " + shell_path(path) + " " + rule + quiet_redirect();
  EXPECT_EQ(shell_exit_code(std::system(add.c_str())), 0);
  auto list = shell_path(*tool) + " schedule list " + shell_path(path) + quiet_redirect();
  EXPECT_EQ(shell_exit_code(std::system(list.c_str())), 0);
  EXPECT_NE(read_text(path).find(rule), std::string::npos);
  std::filesystem::remove(path);
}

TEST(CliUpdate, ServerlistFetchesHttpUrl) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  ed2k::net::IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  server.serve([](tcp::socket s) -> asio::awaitable<void> {
    asio::streambuf request;
    auto [read_ec, read_n] = co_await asio::async_read_until(
      s, request, "\r\n\r\n", asio::as_tuple(asio::use_awaitable));
    (void)read_n;
    if (read_ec) co_return;
    const std::string body = "server-list";
    const std::string response =
      "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    co_await asio::async_write(s, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
    co_return;
  });
  std::thread io_thread([&] { rt.run(); });

  const auto path = std::filesystem::temp_directory_path() / "ed2k_cli_update_server.met";
  std::filesystem::remove(path);
  const std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/server.met";
  const auto command = shell_path(*tool) + " update-serverlist " + url + " " +
                       shell_path(path) + quiet_redirect();
  EXPECT_EQ(shell_exit_code(std::system(command.c_str())), 0);

  rt.stop();
  if (io_thread.joinable()) {
    io_thread.join();
  }
  EXPECT_EQ(read_text(path), "server-list");
  std::filesystem::remove(path);
}

TEST(CliProxy, GlobalProxyRoutesLoginThroughSocks5) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  ed2k::net::IoRuntime rt;
  ed2k::test::MockPeer proxy(rt.context());
  std::vector<std::byte> greeting;
  std::vector<std::byte> connect_request;
  bool saw_login = false;

  proxy.serve([&](tcp::socket s) -> asio::awaitable<void> {
    greeting.resize(3);
    auto [g_ec, g_n] = co_await asio::async_read(s, asio::buffer(greeting), asio::as_tuple(asio::use_awaitable));
    (void)g_n;
    if (g_ec) co_return;

    if (greeting == std::vector<std::byte>{std::byte{0x05}, std::byte{0x01}, std::byte{0x00}}) {
      std::array<std::byte, 2> greet_ok{std::byte{0x05}, std::byte{0x00}};
      co_await asio::async_write(s, asio::buffer(greet_ok), asio::as_tuple(asio::use_awaitable));

      connect_request.resize(10);
      auto [c_ec, c_n] = co_await asio::async_read(s, asio::buffer(connect_request), asio::as_tuple(asio::use_awaitable));
      (void)c_n;
      if (c_ec) co_return;
      std::array<std::byte, 10> connect_ok{
        std::byte{0x05}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}};
      co_await asio::async_write(s, asio::buffer(connect_ok), asio::as_tuple(asio::use_awaitable));
      saw_login = co_await read_ed2k_frame(s);
    }

    co_await ed2k::test::send_packet(s, ed2k::server::op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    co_return;
  });
  std::thread io_thread([&] { rt.run(); });

  ed2k::ServerList list;
  ed2k::ServerEntry entry;
  entry.ip = *ed2k::IPv4::from_dotted("127.0.0.1");
  entry.port = proxy.port();
  list.servers = {entry};
  const auto met_path = std::filesystem::temp_directory_path() / "ed2k_cli_proxy_login_server.met";
  write_bytes(met_path, ed2k::write_server_met(list));

  const std::string proxy_uri = "socks5://127.0.0.1:" + std::to_string(proxy.port());
  const auto command = shell_path(*tool) + " --proxy " + proxy_uri + " login " +
                       shell_arg(shell_path(met_path)) + quiet_redirect();
  EXPECT_EQ(shell_exit_code(std::system(command.c_str())), 0);

  rt.stop();
  if (io_thread.joinable()) {
    io_thread.join();
  }
  std::filesystem::remove(met_path);

  EXPECT_EQ(greeting, (std::vector<std::byte>{std::byte{0x05}, std::byte{0x01}, std::byte{0x00}}));
  ASSERT_EQ(connect_request.size(), 10u);
  EXPECT_EQ(connect_request[0], std::byte{0x05});
  EXPECT_EQ(connect_request[1], std::byte{0x01});
  EXPECT_EQ(connect_request[3], std::byte{0x01});
  EXPECT_EQ(connect_request[4], std::byte{0x7F});
  EXPECT_EQ(connect_request[5], std::byte{0x00});
  EXPECT_EQ(connect_request[6], std::byte{0x00});
  EXPECT_EQ(connect_request[7], std::byte{0x01});
  EXPECT_EQ(connect_request[8], static_cast<std::byte>((proxy.port() >> 8) & 0xffu));
  EXPECT_EQ(connect_request[9], static_cast<std::byte>(proxy.port() & 0xffu));
  EXPECT_TRUE(saw_login);
}

TEST(CliIPFilter, GlobalIpfilterBlocksLoginBeforeConnect) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  ed2k::net::IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  bool saw_login = false;
  server.serve([&](tcp::socket s) -> asio::awaitable<void> {
    saw_login = co_await read_ed2k_frame(s);
    co_await ed2k::test::send_packet(s, ed2k::server::op::IDCHANGE, idchange_payload(0x01000000u, 0x0119u));
    co_return;
  });
  std::thread io_thread([&] { rt.run(); });

  ed2k::ServerList list;
  ed2k::ServerEntry entry;
  entry.ip = *ed2k::IPv4::from_dotted("127.0.0.1");
  entry.port = server.port();
  list.servers = {entry};
  const auto met_path = std::filesystem::temp_directory_path() / "ed2k_cli_ipfilter_login_server.met";
  write_bytes(met_path, ed2k::write_server_met(list));

  const auto filter_path = std::filesystem::temp_directory_path() / "ed2k_cli_block_all_ipfilter.dat";
  {
    std::ofstream out(filter_path, std::ios::binary | std::ios::trunc);
    out << "0.0.0.0,255.255.255.255,200,block all\n";
  }

  const auto command = shell_path(*tool) + " --ipfilter " + shell_arg(shell_path(filter_path)) +
                       " login " + shell_arg(shell_path(met_path)) + quiet_redirect();
  EXPECT_NE(shell_exit_code(std::system(command.c_str())), 0);

  rt.stop();
  if (io_thread.joinable()) {
    io_thread.join();
  }
  std::filesystem::remove(met_path);
  std::filesystem::remove(filter_path);
  EXPECT_FALSE(saw_login);
}

TEST(CliStats, PrintsStatisticsFile) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  const auto path = std::filesystem::temp_directory_path() / "ed2k_cli_statistics.dat";
  ed2k::infra::Statistics stats;
  stats.add_uploaded_bytes(123);
  auto saved = stats.save(path);
  ASSERT_TRUE(saved.has_value()) << saved.error().message();

#ifdef _WIN32
  const std::string redirect = " > NUL";
#else
  const std::string redirect = " > /dev/null";
#endif
  const auto command = shell_path(*tool) + " stats " + shell_path(path) + redirect;
  EXPECT_EQ(shell_exit_code(std::system(command.c_str())), 0);
  std::filesystem::remove(path);
}
