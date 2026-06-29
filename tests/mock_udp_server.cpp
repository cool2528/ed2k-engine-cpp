#include "mock_udp_server.hpp"
#include "ed2k/net/udp_framing.hpp"
#include <utility>
#include <vector>
#include <zlib.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/buffer.hpp>
namespace ed2k::test {
namespace asio = boost::asio;
using udp = asio::ip::udp;
MockUdpServer::MockUdpServer(asio::io_context& ctx)
  : socket_(ctx, udp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0)) {}
std::uint16_t MockUdpServer::port() const { return socket_.local_endpoint().port(); }
void MockUdpServer::serve(std::function<asio::awaitable<void>(udp::socket&, const ed2k::net::Packet&, const udp::endpoint&)> handler){
  asio::co_spawn(socket_.get_executor(),
    [this, handler=std::move(handler)]() -> asio::awaitable<void> {
      std::vector<std::byte> buf(65536); udp::endpoint sender;
      while(true){
        auto [ec,n] = co_await socket_.async_receive_from(asio::buffer(buf), sender, asio::as_tuple(asio::use_awaitable));
        if(ec) co_return;
        auto pkt = ed2k::net::parse_udp_datagram(std::span<const std::byte>{buf.data(), n});
        if(!pkt) continue;
        co_await handler(socket_, *pkt, sender);
      }
    }, asio::detached);
}
asio::awaitable<void> send_packet_to(udp::socket& s, udp::endpoint to, std::uint8_t opcode, std::span<const std::byte> payload){
  ed2k::net::Packet p; p.protocol=ed2k::net::proto::eDonkey; p.opcode=opcode;
  p.payload.assign(payload.begin(), payload.end());
  auto dg = ed2k::net::encode_udp_packet(p);
  auto [e,n] = co_await s.async_send_to(asio::buffer(dg), to, asio::as_tuple(asio::use_awaitable));
  (void)e;(void)n; co_return;
}
asio::awaitable<void> send_zlib_packet_to(udp::socket& s, udp::endpoint to, std::uint8_t opcode, std::span<const std::byte> plain){
  std::vector<std::byte> compressed; compressed.resize(compressBound(static_cast<uLong>(plain.size())));
  uLongf outlen = compressed.size();
  compress(reinterpret_cast<Bytef*>(compressed.data()), &outlen,
           reinterpret_cast<const Bytef*>(plain.data()), static_cast<uLong>(plain.size()));
  compressed.resize(outlen);
  ed2k::net::Packet p; p.protocol=ed2k::net::proto::zlib; p.opcode=opcode; p.payload=std::move(compressed);
  auto dg = ed2k::net::encode_udp_packet(p);
  auto [e,n] = co_await s.async_send_to(asio::buffer(dg), to, asio::as_tuple(asio::use_awaitable));
  (void)e;(void)n; co_return;
}
}
