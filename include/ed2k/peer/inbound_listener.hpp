#pragma once
#include <chrono>
#include <cstdint>
#include <memory>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "ed2k/peer/c2c_connection.hpp"
namespace ed2k::peer {
class InboundListener {
 public:
  InboundListener(boost::asio::any_io_executor ex, std::uint16_t port = 4662);
  std::uint16_t local_port() const noexcept;
  boost::asio::awaitable<tl::expected<boost::asio::ip::tcp::socket, std::error_code>>
    accept(std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<C2CConnection, std::error_code>>
    accept_peer(std::optional<UserHash> local_hash, ObfuscationPolicy policy,
                std::chrono::milliseconds timeout,
                std::shared_ptr<const infra::IPFilter> ip_filter = nullptr,
                std::uint8_t ip_filter_level = 127);
  void close() noexcept;
 private:
  boost::asio::ip::tcp::acceptor acceptor_;
};
}
