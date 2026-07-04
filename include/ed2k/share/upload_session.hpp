#pragma once
#include <chrono>
#include <optional>
#include <system_error>
#include <tl/expected.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "ed2k/net/connection.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/share/known_file.hpp"
#include "ed2k/share/upload_queue.hpp"
#include "ed2k/share/upload_throttler.hpp"

namespace ed2k::share {

class UploadSession {
 public:
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                const KnownFileDB& files,
                ed2k::peer::HelloInfo self);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                const KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                const KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor,
                UploadQueue* queue);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                const KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor,
                UploadQueue* queue,
                UploadBandwidthThrottler* throttler);

  boost::asio::awaitable<tl::expected<void, std::error_code>>
    run(std::chrono::milliseconds timeout);

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
  const KnownFileDB& files_;
  ed2k::peer::HelloInfo self_;
  std::optional<ed2k::peer::HelloInfo> peer_;
  boost::asio::any_io_executor disk_executor_;
  UploadQueue* queue_ = nullptr;
  UploadBandwidthThrottler* throttler_ = nullptr;
};

} // namespace ed2k::share
