#include "mock_peer.hpp"
#include <utility>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
namespace ed2k::test {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
MockPeer::MockPeer(asio::io_context& ctx)
  : acceptor_(ctx, tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0)) {}
std::uint16_t MockPeer::port() const { return acceptor_.local_endpoint().port(); }
void MockPeer::serve(std::function<asio::awaitable<void>(tcp::socket)> handler){
  asio::co_spawn(acceptor_.get_executor(),
    [this, handler = std::move(handler)]() -> asio::awaitable<void> {
      auto [ec, sock] = co_await acceptor_.async_accept(asio::as_tuple(asio::use_awaitable));
      if(ec) co_return;
      { boost::system::error_code ndc; sock.set_option(tcp::no_delay(true), ndc); }   // 禁 Nagle: 测试请求-应答短帧不延迟
      try { co_await handler(std::move(sock)); } catch(...) {}
      co_return;
    }, asio::detached);
}
}
