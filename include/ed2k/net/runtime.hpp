#pragma once
#include <utility>
#include <boost/asio/io_context.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
namespace ed2k::net {
class IoRuntime {
 public:
  boost::asio::any_io_executor executor() { return ctx_.get_executor(); }
  boost::asio::io_context& context() { return ctx_; }
  void run() { ctx_.run(); }
  void restart() { ctx_.restart(); }
  void stop() noexcept { ctx_.stop(); }
  template <class Awaitable>
  void co_spawn_detached(Awaitable&& a){
    boost::asio::co_spawn(ctx_, std::forward<Awaitable>(a), boost::asio::detached);
  }
 private:
  boost::asio::io_context ctx_;
};
}
