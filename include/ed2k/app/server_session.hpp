#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/server/connection.hpp"
#include "ed2k/server/messages.hpp"
namespace ed2k::app {
struct ServerTarget { IPv4 ip; std::uint16_t port = 0; };
struct LoginSession {
  ed2k::server::ServerConnection conn;
  ed2k::server::LoginResult result;
};
std::vector<ServerTarget> fallback_servers();
std::vector<ServerTarget> build_targets(std::span<const std::byte> server_met_bytes,
                                        std::optional<ServerTarget> override);
boost::asio::awaitable<tl::expected<LoginSession, std::error_code>>
  login_with_rotation(boost::asio::any_io_executor ex,
                      std::span<const std::byte> server_met_bytes,
                      std::optional<ServerTarget> override,
                      const ed2k::server::LoginParams& p,
                      std::chrono::milliseconds per_server_timeout);
}
