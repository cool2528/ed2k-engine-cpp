#pragma once

#include <chrono>
#include <cstdint>
#include <span>
#include <system_error>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <tl/expected.hpp>

#include "ed2k/kad/indexed.hpp"
#include "ed2k/kad/messages.hpp"
#include "ed2k/kad/routing_table.hpp"
#include "ed2k/net/udp_socket.hpp"

namespace ed2k::kad {

struct KadNetworkOptions {
  KadID id;
  IPv4 ip;
  std::uint16_t udp_port = 0;
  std::uint16_t tcp_port = 0;
  std::uint8_t version = kad2_version;
};

class KadNetwork {
 public:
  explicit KadNetwork(boost::asio::any_io_executor ex, KadNetworkOptions options);

  const Contact& self_contact() const noexcept { return self_; }
  boost::asio::ip::udp::endpoint local_endpoint() const { return socket_.local_endpoint(); }

  RoutingTable& routing_table() noexcept { return routing_; }
  const RoutingTable& routing_table() const noexcept { return routing_; }

  boost::asio::awaitable<tl::expected<Contact, std::error_code>>
  send_hello(boost::asio::ip::udp::endpoint remote, std::chrono::milliseconds timeout);

  boost::asio::awaitable<tl::expected<std::vector<Contact>, std::error_code>>
  request_closest(const Contact& remote, KadID target, std::uint8_t count, std::chrono::milliseconds timeout);

  boost::asio::awaitable<tl::expected<void, std::error_code>>
  bootstrap(std::span<const Contact> seeds, std::chrono::milliseconds timeout);

  boost::asio::awaitable<tl::expected<KadPublishResponse, std::error_code>>
  publish_keyword(const Contact& remote, KadID key_id, std::span<const KadSearchEntry> entries,
                  std::chrono::milliseconds timeout);

  boost::asio::awaitable<tl::expected<KadPublishResponse, std::error_code>>
  publish_source(const Contact& remote, KadID file_id, const KadSearchEntry& source,
                 std::chrono::milliseconds timeout);

  boost::asio::awaitable<tl::expected<KadPublishResponse, std::error_code>>
  publish_notes(const Contact& remote, KadID file_id, const KadSearchEntry& note,
                std::chrono::milliseconds timeout);

  boost::asio::awaitable<tl::expected<std::vector<KadSearchEntry>, std::error_code>>
  search_keyword(std::span<const Contact> peers, KadID key_id, std::chrono::milliseconds timeout);

  boost::asio::awaitable<tl::expected<std::vector<KadSearchEntry>, std::error_code>>
  find_sources(std::span<const Contact> peers, KadID file_id, std::uint64_t file_size,
               std::chrono::milliseconds timeout);

  boost::asio::awaitable<tl::expected<std::vector<KadSearchEntry>, std::error_code>>
  search_notes(std::span<const Contact> peers, KadID file_id, std::uint64_t file_size,
               std::chrono::milliseconds timeout);

  boost::asio::awaitable<tl::expected<void, std::error_code>>
  serve_once(std::chrono::milliseconds timeout);

  void close() noexcept { socket_.close(); }

 private:
  net::UdpSocket socket_;
  Contact self_;
  RoutingTable routing_;
  KadIndexed indexed_;
};

} // namespace ed2k::kad
