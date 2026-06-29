#include "mock_server.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/net/packet.hpp"
#include <utility>
#include <vector>
#include <zlib.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
namespace ed2k::test {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

MockServer::MockServer(asio::io_context& ctx)
  : acceptor_(ctx, tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0)) {}
std::uint16_t MockServer::port() const { return acceptor_.local_endpoint().port(); }
void MockServer::serve(std::function<asio::awaitable<void>(tcp::socket)> handler){
  asio::co_spawn(acceptor_.get_executor(),
    [this, handler=std::move(handler)]() -> asio::awaitable<void> {
      auto [ec, sock] = co_await acceptor_.async_accept(asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      try { co_await handler(std::move(sock)); } catch(...) {}
      co_return;
    }, asio::detached);
}
asio::awaitable<void> send_packet(tcp::socket& s, std::uint8_t opcode, std::span<const std::byte> payload){
  ed2k::net::Packet p; p.protocol = ed2k::net::proto::eDonkey; p.opcode = opcode;
  p.payload.assign(payload.begin(), payload.end());
  auto frame = ed2k::net::encode_frame(p);
  auto [e,n] = co_await asio::async_write(s, asio::buffer(frame.data(), frame.size()), asio::as_tuple(asio::use_awaitable));
  (void)e;(void)n; co_return;
}
asio::awaitable<void> send_zlib_packet(tcp::socket& s, std::uint8_t opcode, std::span<const std::byte> plain){
  std::vector<std::byte> compressed;
  compressed.resize(compressBound(static_cast<uLong>(plain.size())));
  uLongf outlen = compressed.size();
  compress(reinterpret_cast<Bytef*>(compressed.data()), &outlen,
           reinterpret_cast<const Bytef*>(plain.data()), static_cast<uLong>(plain.size()));
  compressed.resize(outlen);
  ed2k::net::Packet p; p.protocol = ed2k::net::proto::zlib; p.opcode = opcode;
  p.payload = std::move(compressed);
  auto frame = ed2k::net::encode_frame(p);
  auto [e,n] = co_await asio::async_write(s, asio::buffer(frame.data(), frame.size()), asio::as_tuple(asio::use_awaitable));
  (void)e;(void)n; co_return;
}
}
