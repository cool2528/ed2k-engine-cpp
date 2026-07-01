#pragma once
#include <chrono>
#include <cstdint>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
namespace ed2k::peer {
class InboundListener {
 public:
  InboundListener(boost::asio::any_io_executor ex, std::uint16_t port = 4662);
  std::uint16_t local_port() const noexcept;
  boost::asio::awaitable<tl::expected<boost::asio::ip::tcp::socket, std::error_code>>
    accept(std::chrono::milliseconds timeout);
  void close() noexcept;
 private:
  boost::asio::ip::tcp::acceptor acceptor_;
};
}
