#pragma once
#include <chrono>
#include <system_error>
#include <tl/expected.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "ed2k/net/connection.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/share/known_file.hpp"

namespace ed2k::share {

class UploadSession {
 public:
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                const KnownFileDB& files,
                ed2k::peer::HelloInfo self);

  boost::asio::awaitable<tl::expected<void, std::error_code>>
    run(std::chrono::milliseconds timeout);

 private:
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    handshake(std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    handle(const ed2k::net::Packet& pkt);
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    send_not_found(const ed2k::FileHash& hash);

  ed2k::net::Connection conn_;
  const KnownFileDB& files_;
  ed2k::peer::HelloInfo self_;
};

} // namespace ed2k::share
