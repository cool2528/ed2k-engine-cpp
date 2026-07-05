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

struct UdpServerObfuscation {
  std::uint32_t udp_key = 0;
  std::uint16_t udp_port = 0;
  std::chrono::milliseconds probe_timeout{500};
  bool fallback_plain = true;
  std::uint16_t random_key_part = 0;
  std::uint8_t marker = 0;
  bool enabled() const noexcept { return udp_key != 0 && udp_port != 0; }
};

class UdpServerConnection {
 public:
  UdpServerConnection(boost::asio::any_io_executor ex, IPv4 server_ip, std::uint16_t server_udp_port);
  UdpServerConnection(boost::asio::any_io_executor ex, IPv4 server_ip, std::uint16_t server_udp_port,
                      UdpServerObfuscation obfuscation);
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
  boost::asio::ip::udp::endpoint obfuscated_endpoint() const;
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    send_request(const ed2k::net::Packet& request, bool obfuscated);
  boost::asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
    request_response(const ed2k::net::Packet& request, std::uint8_t want, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
    pump_until(std::uint8_t want, std::chrono::milliseconds budget);
  ed2k::net::UdpSocket sock_;
  boost::asio::ip::udp::endpoint plain_server_;
  UdpServerObfuscation obfuscation_;
  std::function<void(const UdpEvent&)> on_event_;
};
}
