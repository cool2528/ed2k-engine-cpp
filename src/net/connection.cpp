#include "ed2k/net/connection.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/util/error.hpp"
#include <array>
#include <vector>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
namespace ed2k::net {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

Connection::Connection(asio::any_io_executor ex) : socket_(ex) {}
void Connection::close() noexcept { boost::system::error_code ig; socket_.cancel(ig); socket_.close(ig); }
bool Connection::is_open() const noexcept { return socket_.is_open(); }

asio::awaitable<tl::expected<void,std::error_code>>
Connection::connect(IPv4 ip, std::uint16_t port, std::chrono::milliseconds timeout){
  tcp::endpoint ep(asio::ip::address_v4(ip.host()), port);
  auto [ec] = co_await socket_.async_connect(
      ep, asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  if(ec){
    if(ec == asio::error::operation_aborted) co_return tl::unexpected(make_error_code(errc::timed_out));
    co_return tl::unexpected(make_error_code(errc::connect_failed));
  }
  // TCP_NODELAY: 禁用 Nagle —— 请求-应答短帧 (AICH proof 等) 不被小帧合并延迟 (client 侧)。
  { boost::system::error_code ndc; socket_.set_option(tcp::no_delay(true), ndc); }
  co_return tl::expected<void,std::error_code>{};
}

asio::awaitable<tl::expected<void,std::error_code>>
Connection::send(const Packet& p){
  auto frame = encode_frame(p);
  auto [ec,n] = co_await asio::async_write(
      socket_, asio::buffer(frame.data(), frame.size()), asio::as_tuple(asio::use_awaitable));
  if(ec) co_return tl::unexpected(make_error_code(errc::connection_closed));
  co_return tl::expected<void,std::error_code>{};
}

asio::awaitable<tl::expected<Packet,std::error_code>>
Connection::recv(std::chrono::milliseconds timeout){
  std::array<std::byte,5> hdr;
  {
    auto [ec,n] = co_await asio::async_read(
        socket_, asio::buffer(hdr.data(), hdr.size()),
        asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
    if(ec){
      if(ec == asio::error::operation_aborted) co_return tl::unexpected(make_error_code(errc::timed_out));
      co_return tl::unexpected(make_error_code(errc::connection_closed));
    }
  }
  auto h = parse_header(hdr);
  if(!h) co_return tl::unexpected(h.error());
  std::vector<std::byte> body(h->size);
  {
    auto [ec,n] = co_await asio::async_read(
        socket_, asio::buffer(body.data(), body.size()),
        asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
    if(ec){
      if(ec == asio::error::operation_aborted) co_return tl::unexpected(make_error_code(errc::timed_out));
      co_return tl::unexpected(make_error_code(errc::connection_closed));
    }
  }
  co_return assemble(h->protocol, body);
}
}
