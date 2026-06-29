#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <utility>
#include <variant>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/net/udp_socket.hpp"
#include "ed2k/server/udp_messages.hpp"
#include "ed2k/server/search_query.hpp"
namespace ed2k::server {
struct InvalidLowIdEvent { std::uint32_t id=0; };
using UdpEvent = std::variant<InvalidLowIdEvent>;

class UdpServerConnection {
 public:
  UdpServerConnection(boost::asio::any_io_executor ex, IPv4 server_ip, std::uint16_t server_udp_port);
  void on_event(std::function<void(const UdpEvent&)> sink);

  boost::asio::awaitable<tl::expected<UdpSearchResult,std::error_code>>
    global_search(const SearchExpr&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<FoundSources,std::error_code>>
    get_sources(const FileHash&, std::uint64_t size, std::chrono::milliseconds timeout);
  // Task 6 追加: server_status / server_list / server_desc
  boost::asio::awaitable<tl::expected<ServerStat,std::error_code>>
    server_status(std::uint32_t challenge, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<std::pair<IPv4,std::uint16_t>>,std::error_code>>
    server_list(IPv4 ask_ip, std::uint16_t ask_port, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<ServerDesc,std::error_code>>
    server_desc(std::uint32_t challenge, std::chrono::milliseconds timeout);
  void close() noexcept;
 private:
  boost::asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
    pump_until(std::uint8_t want, std::chrono::milliseconds budget);
  ed2k::net::UdpSocket sock_;
  boost::asio::ip::udp::endpoint server_;
  std::function<void(const UdpEvent&)> on_event_;
};
}
