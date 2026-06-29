#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
namespace ed2k::test {
class MockServer {
 public:
  explicit MockServer(boost::asio::io_context& ctx);
  std::uint16_t port() const;
  void serve(std::function<boost::asio::awaitable<void>(boost::asio::ip::tcp::socket)> handler);
 private:
  boost::asio::ip::tcp::acceptor acceptor_;
};
// 在 handler 协程里发一个 eD2k 帧（0xE3 + size + opcode + payload）；payload 默认空
boost::asio::awaitable<void> send_packet(boost::asio::ip::tcp::socket& s, std::uint8_t opcode,
                                         std::span<const std::byte> payload = {});
// 发 zlib 压缩帧（0xD4）：把明文 payload 压缩后发出，P2 recv 透明解压
boost::asio::awaitable<void> send_zlib_packet(boost::asio::ip::tcp::socket& s, std::uint8_t opcode,
                                              std::span<const std::byte> plain);
}
