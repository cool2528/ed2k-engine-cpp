#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <variant>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include "ed2k/core/hash.hpp"          // MD4Hash/IPv4/FileHash
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/net/connection.hpp"     // net::Connection
#include "ed2k/server/messages.hpp"    // LoginParams/SearchResultItem/FoundSources/decode_*
#include "ed2k/server/search_query.hpp"// SearchExpr
#include "ed2k/share/known_file.hpp"
namespace ed2k::server {

struct LoginResult { std::uint32_t client_id=0, flags=0; bool high_id=false; };

struct ServerStatusEvent      { std::uint32_t users=0, files=0; };
struct ServerMessageEvent     { std::string text; };
struct ServerIdentEvent       { MD4Hash hash; IPv4 ip; std::uint16_t port=0; std::string name, description; };
struct ServerListEvent        { std::vector<std::pair<IPv4,std::uint16_t>> servers; };
struct CallbackRequestedEvent { IPv4 ip; std::uint16_t port=0; };
using ServerEvent = std::variant<ServerStatusEvent, ServerMessageEvent, ServerIdentEvent,
                                 ServerListEvent, CallbackRequestedEvent>;

class ServerConnection {
 public:
  explicit ServerConnection(boost::asio::any_io_executor ex);
  void on_event(std::function<void(const ServerEvent&)> sink);
  void set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level = 127);

  boost::asio::awaitable<tl::expected<LoginResult,std::error_code>>
    connect_and_login(IPv4 ip, std::uint16_t port, const LoginParams&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<SearchResultItem>,std::error_code>>
    search(const SearchExpr&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<FoundSources,std::error_code>>
    get_sources(const FileHash&, std::uint64_t size, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    callback_request(std::uint32_t client_id, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    publish_files(std::span<const ed2k::share::KnownFile> files);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    receive_events(std::chrono::milliseconds timeout);
  void close() noexcept;
  bool is_open() const noexcept;
 private:
  boost::asio::awaitable<tl::expected<net::Packet,std::error_code>>
    pump_until(std::uint8_t want_opcode, std::chrono::milliseconds total_budget);
  void dispatch_push(const net::Packet& pkt);
  net::Connection conn_;
  std::function<void(const ServerEvent&)> on_event_;
};
}
