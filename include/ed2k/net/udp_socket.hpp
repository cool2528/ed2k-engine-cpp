#pragma once
#include <chrono>
#include <cstdint>
#include <system_error>
#include <utility>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <tl/expected.hpp>
#include "ed2k/net/packet.hpp"
namespace ed2k::net {
class UdpSocket {
 public:
  explicit UdpSocket(boost::asio::any_io_executor ex, std::uint16_t bind_port = 0);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    send_to(boost::asio::ip::udp::endpoint ep, const Packet& p);
  boost::asio::awaitable<tl::expected<std::pair<Packet,boost::asio::ip::udp::endpoint>,std::error_code>>
    recv_from(std::chrono::milliseconds timeout);
  boost::asio::ip::udp::endpoint local_endpoint() const;
  void close() noexcept;
  bool is_open() const noexcept;
 private:
  boost::asio::ip::udp::socket socket_;
};
}
