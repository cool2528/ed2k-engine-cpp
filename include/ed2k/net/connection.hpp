#pragma once
#include <chrono>
#include <cstdint>
#include <system_error>
#include <utility>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"     // IPv4
#include "ed2k/net/packet.hpp"
namespace ed2k::net {
class Connection {
 public:
  explicit Connection(boost::asio::any_io_executor ex);
  explicit Connection(boost::asio::ip::tcp::socket&& s) : socket_(std::move(s)) {
    // TCP_NODELAY: eD2k 为短帧请求-应答协议 (AICH proof/REQUESTPARTS 等), 禁用 Nagle
    // 避免小帧等对端 delayed-ACK 造成 ~200ms/轮次的停顿 (accept 侧: LowID 回调接入的 socket)。
    boost::system::error_code ec;
    socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
  }
  Connection(Connection&&) noexcept = default;
  Connection& operator=(Connection&&) noexcept = default;

  boost::asio::awaitable<tl::expected<void,std::error_code>>
    connect(IPv4 ip, std::uint16_t port, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    send(const Packet& p);
  boost::asio::awaitable<tl::expected<Packet,std::error_code>>
    recv(std::chrono::milliseconds timeout);
  void close() noexcept;
  bool is_open() const noexcept;
 private:
  boost::asio::ip::tcp::socket socket_;
};
}
