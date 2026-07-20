#pragma once
#include <chrono>
#include <cstddef>
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
#include "ed2k/infra/proxy.hpp"
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
    friend class ServerConnection;
    Subscription(std::weak_ptr<SubscriptionState> state, std::size_t id) noexcept;
    void reset() noexcept;

    std::weak_ptr<SubscriptionState> state_;
    std::size_t id_ = 0;
  };

  explicit ServerConnection(boost::asio::any_io_executor ex);
  ~ServerConnection();
  ServerConnection(const ServerConnection&) = delete;
  ServerConnection& operator=(const ServerConnection&) = delete;
  ServerConnection(ServerConnection&&) noexcept;
  ServerConnection& operator=(ServerConnection&&) noexcept;

  [[nodiscard]] Subscription on_event(std::function<void(const ServerEvent&)> sink);
  void set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level = 127);

  boost::asio::awaitable<tl::expected<LoginResult,std::error_code>>
    connect_and_login(IPv4 ip, std::uint16_t port, const LoginParams&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<LoginResult,std::error_code>>
    connect_and_login_via_proxy(const infra::ProxyConfig& proxy,
                                IPv4 ip,
                                std::uint16_t port,
                                const LoginParams&,
                                std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<SearchResultItem>,std::error_code>>
    search(const SearchExpr&, std::chrono::milliseconds timeout);
  // 请求上一次 search 的后续批次结果(eMule OP_QUERY_MORE_RESULT)。
  // 必须在同一连接上 search 成功之后串行调用; 服务器端到底时通常直接超时或回空列表。
  boost::asio::awaitable<tl::expected<std::vector<SearchResultItem>,std::error_code>>
    search_more(std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<FoundSources,std::error_code>>
    get_sources(const FileHash&, std::uint64_t size, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<std::pair<IPv4,std::uint16_t>>,std::error_code>>
    get_server_list(std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    callback_request(std::uint32_t client_id, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    publish_files(std::span<const ed2k::share::KnownFile> files);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    receive_events(std::chrono::milliseconds timeout);
  void close() noexcept;
  bool is_open() const noexcept;
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}
