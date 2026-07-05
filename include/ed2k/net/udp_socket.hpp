#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>
#include <utility>
#include <vector>
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
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    send_datagram(boost::asio::ip::udp::endpoint ep, std::span<const std::byte> datagram);
  boost::asio::awaitable<tl::expected<std::pair<std::vector<std::byte>,boost::asio::ip::udp::endpoint>,std::error_code>>
    recv_datagram(std::chrono::milliseconds timeout);
  boost::asio::ip::udp::endpoint local_endpoint() const;
  void close() noexcept;
  bool is_open() const noexcept;
 private:
  boost::asio::ip::udp::socket socket_;
};
}
