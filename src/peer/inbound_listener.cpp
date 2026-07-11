#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/util/error.hpp"
#include "ed2k/net/encrypted_stream_socket.hpp"
#include "ed2k/net/packet.hpp"
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/buffer.hpp>
namespace ed2k::peer {
namespace asio = boost::asio; using tcp = asio::ip::tcp;
using clock_type = std::chrono::steady_clock;
namespace {
std::optional<std::chrono::milliseconds> remaining(clock_type::time_point deadline) {
  auto value = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
  if (value.count() <= 0) return std::nullopt;
  return value;
}
}
InboundListener::InboundListener(asio::any_io_executor ex, std::uint16_t port)
  : acceptor_(ex, tcp::endpoint(asio::ip::address_v4::any(), port)) {
  acceptor_.set_option(asio::socket_base::reuse_address(true));
}
std::uint16_t InboundListener::local_port() const noexcept {
  boost::system::error_code ig; return acceptor_.local_endpoint(ig).port();
}
asio::awaitable<tl::expected<tcp::socket, std::error_code>>
InboundListener::accept(std::chrono::milliseconds timeout){
  auto [ec, sock] = co_await acceptor_.async_accept(
    asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  if(ec){
    if(ec == asio::error::operation_aborted) co_return tl::unexpected(make_error_code(errc::timed_out));
    co_return tl::unexpected(make_error_code(errc::connection_closed));
  }
  co_return std::move(sock);
}
asio::awaitable<tl::expected<C2CConnection, std::error_code>>
InboundListener::accept_peer(std::optional<UserHash> local_hash,
                             ObfuscationPolicy policy,
                             std::chrono::milliseconds timeout,
                             std::shared_ptr<const infra::IPFilter> ip_filter,
                             std::uint8_t ip_filter_level) {
  const auto deadline = clock_type::now() + timeout;
  auto budget = remaining(deadline);
  if (!budget) co_return tl::unexpected(make_error_code(errc::timed_out));
  auto accepted = co_await accept(*budget);
  if (!accepted) co_return tl::unexpected(accepted.error());
  auto socket = std::move(*accepted);

  boost::system::error_code remote_ec;
  auto remote_endpoint = socket.remote_endpoint(remote_ec);
  std::optional<IPv4> remote;
  if (!remote_ec && remote_endpoint.address().is_v4()) {
    remote = IPv4::from_host(remote_endpoint.address().to_v4().to_uint());
    if (ip_filter && ip_filter->blocked(*remote, ip_filter_level)) {
      socket.close();
      co_return tl::unexpected(make_error_code(errc::ip_filtered));
    }
  }

  std::byte first{};
  budget = remaining(deadline);
  if (!budget) {
    socket.close();
    co_return tl::unexpected(make_error_code(errc::timed_out));
  }
  auto [peek_ec, count] = co_await socket.async_receive(
      asio::buffer(&first, 1), tcp::socket::message_peek,
      asio::cancel_after(*budget, asio::as_tuple(asio::use_awaitable)));
  if (peek_ec || count != 1) {
    socket.close();
    if (peek_ec == asio::error::operation_aborted)
      co_return tl::unexpected(make_error_code(errc::timed_out));
    co_return tl::unexpected(make_error_code(errc::connection_closed));
  }

  const auto marker = std::to_integer<std::uint8_t>(first);
  const bool plain = marker == net::proto::eDonkey || marker == net::proto::eMule ||
                     marker == net::proto::zlib;
  if (plain) {
    if (policy == ObfuscationPolicy::required) {
      socket.close();
      co_return tl::unexpected(make_error_code(errc::server_protocol_error));
    }
    co_return C2CConnection(std::move(socket));
  }

  if (policy == ObfuscationPolicy::disabled || !local_hash) {
    socket.close();
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  net::EncryptedStreamSocket encrypted(std::move(socket));
  budget = remaining(deadline);
  if (!budget) co_return tl::unexpected(make_error_code(errc::timed_out));
  auto negotiated = co_await encrypted.handshake_acceptor(*local_hash, *budget);
  if (!negotiated) co_return tl::unexpected(negotiated.error());
  co_return C2CConnection(std::move(encrypted), std::move(remote));
}
void InboundListener::close() noexcept { boost::system::error_code ig; acceptor_.close(ig); }
}
