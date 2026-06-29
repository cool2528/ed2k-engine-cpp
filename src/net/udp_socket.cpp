#include "ed2k/net/udp_socket.hpp"
#include "ed2k/net/udp_framing.hpp"
#include "ed2k/util/error.hpp"
#include <vector>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
namespace ed2k::net {
namespace asio = boost::asio;
using udp = asio::ip::udp;

UdpSocket::UdpSocket(asio::any_io_executor ex, std::uint16_t bind_port)
  : socket_(ex, udp::endpoint(asio::ip::make_address_v4("0.0.0.0"), bind_port)) {}
void UdpSocket::close() noexcept { boost::system::error_code ig; socket_.cancel(ig); socket_.close(ig); }
bool UdpSocket::is_open() const noexcept { return socket_.is_open(); }
udp::endpoint UdpSocket::local_endpoint() const { return socket_.local_endpoint(); }

asio::awaitable<tl::expected<void,std::error_code>>
UdpSocket::send_to(udp::endpoint ep, const Packet& p){
  auto dg = encode_udp_packet(p);
  auto [ec,n] = co_await socket_.async_send_to(asio::buffer(dg.data(), dg.size()), ep,
                                                asio::as_tuple(asio::use_awaitable));
  (void)n;
  if(ec) co_return tl::unexpected(make_error_code(errc::connection_closed));
  co_return tl::expected<void,std::error_code>{};
}
asio::awaitable<tl::expected<std::pair<Packet,udp::endpoint>,std::error_code>>
UdpSocket::recv_from(std::chrono::milliseconds timeout){
  std::vector<std::byte> buf(65536);                  // UDP 数据报 ≤ 64KiB
  udp::endpoint sender;
  auto [ec,n] = co_await socket_.async_receive_from(asio::buffer(buf), sender,
                    asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  if(ec){
    if(ec == asio::error::operation_aborted) co_return tl::unexpected(make_error_code(errc::timed_out));
    co_return tl::unexpected(make_error_code(errc::connection_closed));
  }
  auto pkt = parse_udp_datagram(std::span<const std::byte>{buf.data(), n});
  if(!pkt) co_return tl::unexpected(pkt.error());
  co_return std::make_pair(std::move(*pkt), sender);
}
}
