#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/util/error.hpp"
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/error.hpp>
namespace ed2k::peer {
namespace asio = boost::asio; using tcp = asio::ip::tcp;
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
void InboundListener::close() noexcept { boost::system::error_code ig; acceptor_.close(ig); }
}
