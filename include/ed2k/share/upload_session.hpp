#pragma once
#include <chrono>
#include <memory>
#include <optional>
#include <system_error>
#include <tl/expected.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/net/connection.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/share/client_credits.hpp"
#include "ed2k/share/known_file.hpp"
#include "ed2k/share/upload_queue.hpp"
#include "ed2k/share/upload_throttler.hpp"

namespace ed2k::share {

class UploadSession {
 public:
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor,
                UploadQueue* queue);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor,
                UploadQueue* queue,
                UploadBandwidthThrottler* throttler);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor,
                UploadQueue* queue,
                UploadBandwidthThrottler* throttler,
                ClientCredits* credits);

  boost::asio::awaitable<tl::expected<void, std::error_code>>
    run(std::chrono::milliseconds timeout);
  void set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level = 127);

 private:
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    handshake(std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    handle(const ed2k::net::Packet& pkt);
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    send_not_found(const ed2k::FileHash& hash);
  boost::asio::awaitable<tl::expected<std::vector<std::byte>, std::error_code>>
    read_range(const KnownFile& file, std::uint64_t start, std::uint64_t end);
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    send_requested_parts(const KnownFile& file, const ed2k::peer::RequestParts& req);

  ed2k::net::Connection conn_;
  KnownFileDB& files_;
  ed2k::peer::HelloInfo self_;
  std::optional<ed2k::peer::HelloInfo> peer_;
  std::optional<ed2k::FileHash> current_file_;
  boost::asio::any_io_executor disk_executor_;
  UploadQueue* queue_ = nullptr;
  UploadBandwidthThrottler* throttler_ = nullptr;
  ClientCredits* credits_ = nullptr;
  std::shared_ptr<const infra::IPFilter> ip_filter_;
  std::uint8_t ip_filter_level_ = 127;
};

} // namespace ed2k::share
