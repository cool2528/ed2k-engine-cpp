#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <span>
#include <vector>

#include <boost/asio/co_spawn.hpp>

#include "ed2k/kad/kad_id.hpp"
#include "ed2k/kad/network.hpp"
#include "ed2k/kad/nodes_dat.hpp"
#include "ed2k/net/runtime.hpp"
#include "live_env.hpp"

using namespace ed2k;
namespace asio = boost::asio;
using namespace std::chrono_literals;

namespace {
constexpr std::size_t k_live_seed_limit = 256;

template <class F>
void run_coro(ed2k::net::IoRuntime& rt, F&& body) {
  bool done = false;
  asio::co_spawn(
      rt.context(),
      [&]() -> asio::awaitable<void> {
        co_await body();
        done = true;
        co_return;
      },
      [&](std::exception_ptr e) {
        rt.stop();
        if (e) {
          std::rethrow_exception(e);
        }
      });
  rt.run();
  rt.restart();
  EXPECT_TRUE(done);
}

std::vector<std::byte> read_all(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  in.seekg(0, std::ios::end);
  const auto size = in.tellg();
  in.seekg(0);
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  if (!bytes.empty()) {
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }
  return bytes;
}
} // namespace

TEST(LiveKad, BootstrapFromNodesDatLearnsContacts) {
  if (!ed2k::test::live_enabled()) {
    GTEST_SKIP() << "set ED2K_LIVE=1 ED2K_KAD_NODES=<nodes.dat>";
  }
  const char* nodes_path = std::getenv("ED2K_KAD_NODES");
  if (!nodes_path || !*nodes_path) {
    GTEST_SKIP() << "set ED2K_KAD_NODES=<nodes.dat>";
  }
  if (!std::filesystem::exists(nodes_path)) {
    GTEST_SKIP() << "ED2K_KAD_NODES does not exist";
  }

  auto contacts = ed2k::kad::parse_nodes_dat(read_all(nodes_path));
  ASSERT_TRUE(contacts.has_value()) << (contacts ? "" : contacts.error().message());
  if (contacts->empty()) {
    GTEST_SKIP() << "ED2K_KAD_NODES contains no contacts";
  }

  ed2k::net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    auto user_hash = *ed2k::UserHash::from_hex("0123456789abcdeffedcba9876543210");
    ed2k::kad::KadNetwork network(rt.executor(), ed2k::kad::KadNetworkOptions{
      .id = ed2k::kad::KadID::from_user_hash(user_hash, 1),
      .ip = ed2k::IPv4::from_dotted("0.0.0.0").value(),
      .tcp_port = 4662,
      .version = ed2k::kad::kad2_version,
      .user_hash = ed2k::kad::KadID::from_bytes(user_hash.bytes()),
    });

    const auto seed_count = std::min(contacts->size(), k_live_seed_limit);
    auto bootstrapped = co_await network.bootstrap(
        std::span<const ed2k::kad::Contact>(contacts->data(), seed_count), 1500ms);
    EXPECT_TRUE(bootstrapped.has_value()) << (bootstrapped ? "" : bootstrapped.error().message());
    if (!bootstrapped) {
      co_return;
    }
    EXPECT_GT(network.routing_table().size(), 0u);
    std::printf("  kad_contacts=%zu udp_port=%u\n",
                network.routing_table().size(), network.self_contact().udp_port);
    co_return;
  });
}
