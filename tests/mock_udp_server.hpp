#pragma once
#include <cstdint>
#include <functional>
#include <span>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include "ed2k/net/packet.hpp"
namespace ed2k::test {
class MockUdpServer {
 public:
  explicit MockUdpServer(boost::asio::io_context& ctx);
  std::uint16_t port() const;
  void serve(std::function<boost::asio::awaitable<void>(boost::asio::ip::udp::socket&,
              const ed2k::net::Packet&, const boost::asio::ip::udp::endpoint&)> handler);
 private:
  boost::asio::ip::udp::socket socket_;
};
boost::asio::awaitable<void> send_packet_to(boost::asio::ip::udp::socket& s, boost::asio::ip::udp::endpoint to,
                                            std::uint8_t opcode, std::span<const std::byte> payload = {});
boost::asio::awaitable<void> send_zlib_packet_to(boost::asio::ip::udp::socket& s, boost::asio::ip::udp::endpoint to,
                                                 std::uint8_t opcode, std::span<const std::byte> plain);
}
