#include "ed2k/net/connection.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/util/error.hpp"
#include <array>
#include <string>
#include <utility>
#include <vector>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/read_until.hpp>
namespace ed2k::net {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

Connection::Connection(asio::any_io_executor ex) : socket_(ex) {}
void Connection::close() noexcept { boost::system::error_code ig; socket_.cancel(ig); socket_.close(ig); }
bool Connection::is_open() const noexcept { return socket_.is_open(); }
void Connection::set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level) {
  ip_filter_ = std::move(filter);
  ip_filter_level_ = level;
}

std::optional<IPv4> Connection::remote_ip() const {
  boost::system::error_code ec;
  auto endpoint = socket_.remote_endpoint(ec);
  if (ec || !endpoint.address().is_v4()) {
    return std::nullopt;
  }
  return IPv4::from_host(endpoint.address().to_v4().to_uint());
}

asio::awaitable<tl::expected<void,std::error_code>>
Connection::connect(IPv4 ip, std::uint16_t port, std::chrono::milliseconds timeout){
  if (ip_filter_ && ip_filter_->blocked(ip, ip_filter_level_)) {
    co_return tl::unexpected(make_error_code(errc::ip_filtered));
  }
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
Connection::connect_via_proxy(const infra::ProxyConfig& proxy,
                              IPv4 target_ip,
                              std::uint16_t target_port,
                              std::chrono::milliseconds timeout) {
  if (ip_filter_ && ip_filter_->blocked(target_ip, ip_filter_level_)) {
    co_return tl::unexpected(make_error_code(errc::ip_filtered));
  }

  tcp::resolver resolver(socket_.get_executor());
  auto [resolve_ec, endpoints] = co_await resolver.async_resolve(
      proxy.host,
      std::to_string(proxy.port),
      asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  if(resolve_ec) {
    co_return tl::unexpected(make_error_code(errc::connect_failed));
  }
  auto [connect_ec, endpoint] = co_await asio::async_connect(
      socket_,
      endpoints,
      asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  (void)endpoint;
  if(connect_ec) {
    if(connect_ec == asio::error::operation_aborted) co_return tl::unexpected(make_error_code(errc::timed_out));
    co_return tl::unexpected(make_error_code(errc::connect_failed));
  }
  { boost::system::error_code ndc; socket_.set_option(tcp::no_delay(true), ndc); }

  if(proxy.type == infra::ProxyType::Socks5) {
    std::array<std::byte, 3> greeting{std::byte{0x05}, std::byte{0x01}, std::byte{0x00}};
    auto [write_ec, write_n] = co_await asio::async_write(
        socket_, asio::buffer(greeting),
        asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
    (void)write_n;
    if(write_ec) co_return tl::unexpected(make_error_code(errc::connection_closed));

    std::array<std::byte, 2> greeting_answer{};
    auto [read_ec, read_n] = co_await asio::async_read(
        socket_, asio::buffer(greeting_answer),
        asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
    (void)read_n;
    if(read_ec) {
      if(read_ec == asio::error::operation_aborted) co_return tl::unexpected(make_error_code(errc::timed_out));
      co_return tl::unexpected(make_error_code(errc::connection_closed));
    }
    if(greeting_answer[0] != std::byte{0x05} || greeting_answer[1] != std::byte{0x00}) {
      co_return tl::unexpected(make_error_code(errc::connect_failed));
    }

    const auto host = target_ip.host();
    std::array<std::byte, 10> request{
      std::byte{0x05}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
      static_cast<std::byte>((host >> 24) & 0xFFu),
      static_cast<std::byte>((host >> 16) & 0xFFu),
      static_cast<std::byte>((host >> 8) & 0xFFu),
      static_cast<std::byte>(host & 0xFFu),
      static_cast<std::byte>((target_port >> 8) & 0xFFu),
      static_cast<std::byte>(target_port & 0xFFu)};
    auto [req_ec, req_n] = co_await asio::async_write(
        socket_, asio::buffer(request),
        asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
    (void)req_n;
    if(req_ec) co_return tl::unexpected(make_error_code(errc::connection_closed));

    std::array<std::byte, 10> answer{};
    auto [ans_ec, ans_n] = co_await asio::async_read(
        socket_, asio::buffer(answer),
        asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
    (void)ans_n;
    if(ans_ec) {
      if(ans_ec == asio::error::operation_aborted) co_return tl::unexpected(make_error_code(errc::timed_out));
      co_return tl::unexpected(make_error_code(errc::connection_closed));
    }
    if(answer[0] != std::byte{0x05} || answer[1] != std::byte{0x00}) {
      co_return tl::unexpected(make_error_code(errc::connect_failed));
    }
    co_return tl::expected<void,std::error_code>{};
  }

  const std::string target = target_ip.to_dotted() + ":" + std::to_string(target_port);
  const std::string request =
    "CONNECT " + target + " HTTP/1.1\r\n"
    "Host: " + target + "\r\n\r\n";
  auto [write_ec, write_n] = co_await asio::async_write(
      socket_, asio::buffer(request),
      asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  (void)write_n;
  if(write_ec) co_return tl::unexpected(make_error_code(errc::connection_closed));

  asio::streambuf response;
  auto [read_ec, read_n] = co_await asio::async_read_until(
      socket_, response, "\r\n\r\n",
      asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  (void)read_n;
  if(read_ec) {
    if(read_ec == asio::error::operation_aborted) co_return tl::unexpected(make_error_code(errc::timed_out));
    co_return tl::unexpected(make_error_code(errc::connection_closed));
  }
  const std::string text(asio::buffers_begin(response.data()), asio::buffers_end(response.data()));
  if(text.find(" 200 ") == std::string::npos && text.find(" 200\r\n") == std::string::npos) {
    co_return tl::unexpected(make_error_code(errc::connect_failed));
  }
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
