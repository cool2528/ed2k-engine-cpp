#pragma once
#include <utility>
#include <boost/asio/io_context.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/thread_pool.hpp>
namespace ed2k::net {
class IoRuntime {
 public:
  boost::asio::any_io_executor executor() { return ctx_.get_executor(); }
  // P4c-3 M3: disk/hash 卸载线程池(单线程 inherently 串行化 f_ 访问, 无需 strand)。
  // 网络线程 co_await post(disk_executor()) 期间挂起, 不阻塞其他 worker 的 socket I/O。
  boost::asio::any_io_executor disk_executor() { return disk_pool_.get_executor(); }
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
  boost::asio::thread_pool disk_pool_{1};   // M3: 磁盘写 + part-MD4 卸载(单线程串行 f_)
};
}
