#pragma once
#include <cstdint>
#include <functional>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
namespace ed2k::test {
// 在 127.0.0.1:0 监听，accept 一个连接后把 socket 交给 handler 协程。
class MockPeer {
 public:
  explicit MockPeer(boost::asio::io_context& ctx);
  std::uint16_t port() const;
  void serve(std::function<boost::asio::awaitable<void>(boost::asio::ip::tcp::socket)> handler);
 private:
  boost::asio::ip::tcp::acceptor acceptor_;
};
}
