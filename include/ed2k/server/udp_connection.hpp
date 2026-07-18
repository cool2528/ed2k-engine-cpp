#pragma once
#include <cstddef>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
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
struct UdpServerIdentEvent { MD4Hash hash; IPv4 ip; std::uint16_t port=0; std::string name, description; };
using UdpEvent = std::variant<InvalidLowIdEvent, UdpServerIdentEvent>;

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
  struct SubscriptionState;
 public:
  class Subscription {
   public:
    Subscription() noexcept = default;
    ~Subscription();
    Subscription(const Subscription&) = delete;
    Subscription& operator=(const Subscription&) = delete;
    Subscription(Subscription&& other) noexcept;
    Subscription& operator=(Subscription&& other) noexcept;

   private:
    friend class UdpServerConnection;
    Subscription(std::weak_ptr<SubscriptionState> state, std::size_t id) noexcept;
    void reset() noexcept;

    std::weak_ptr<SubscriptionState> state_;
    std::size_t id_ = 0;
  };

  UdpServerConnection(boost::asio::any_io_executor ex, IPv4 server_ip, std::uint16_t server_udp_port);
  UdpServerConnection(boost::asio::any_io_executor ex, IPv4 server_ip, std::uint16_t server_udp_port,
                      UdpServerObfuscation obfuscation);
  [[nodiscard]] Subscription on_event(std::function<void(const UdpEvent&)> sink);

  boost::asio::awaitable<tl::expected<UdpSearchResult,std::error_code>>
    global_search(const SearchExpr&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<FoundSources,std::error_code>>
    get_sources(const FileHash&, std::uint64_t size, std::chrono::milliseconds timeout);
  // Task 6 additions: server_status / server_list / server_desc
  boost::asio::awaitable<tl::expected<ServerStat,std::error_code>>
    server_status(std::uint32_t challenge, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<std::pair<IPv4,std::uint16_t>>,std::error_code>>
    server_list(IPv4 ask_ip, std::uint16_t ask_port, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<ServerDesc,std::error_code>>
    server_desc(std::uint32_t challenge, std::chrono::milliseconds timeout);
  // Diagnostic for sequential request use. Like the request operations themselves,
  // this connection is not safe for concurrent calls.
  [[nodiscard]] bool last_response_encrypted() const noexcept { return last_response_encrypted_; }
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
  bool last_response_encrypted_ = false;
  std::shared_ptr<SubscriptionState> observers_;
};
}
