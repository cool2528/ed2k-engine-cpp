#pragma once
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"     // IPv4
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/infra/proxy.hpp"
#include "ed2k/net/packet.hpp"
namespace ed2k::net {
class Connection {
 public:
  explicit Connection(boost::asio::any_io_executor ex);
  explicit Connection(boost::asio::ip::tcp::socket&& s);
  ~Connection();
  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = delete;
  Connection(Connection&&) noexcept;
  Connection& operator=(Connection&&) noexcept;

  boost::asio::awaitable<tl::expected<void,std::error_code>>
    connect(IPv4 ip, std::uint16_t port, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    connect_via_proxy(const infra::ProxyConfig& proxy,
                      IPv4 target_ip,
                      std::uint16_t target_port,
                      std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    send(const Packet& p);
  boost::asio::awaitable<tl::expected<Packet,std::error_code>>
    recv(std::chrono::milliseconds timeout);
  boost::asio::any_io_executor executor();
  void set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level = 127);
  std::optional<IPv4> remote_ip() const;
  void close() noexcept;
  bool is_open() const noexcept;
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}
