#pragma once
#include <cstddef>
#include <memory>
#include <utility>
#include <boost/asio/io_context.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
namespace ed2k::net {
class IoRuntime {
 public:
  static constexpr std::size_t disk_pool_thread_count = 1;

  IoRuntime();
  ~IoRuntime();
  IoRuntime(const IoRuntime&) = delete;
  IoRuntime& operator=(const IoRuntime&) = delete;
  IoRuntime(IoRuntime&&) = delete;
  IoRuntime& operator=(IoRuntime&&) = delete;

  boost::asio::any_io_executor executor();
  // P4c-3 M3/R1-3 S3: disk/hash 卸载线程池(单线程 inherently 串行化 f_ 访问, 无需 strand)。
  // 改成 >1 前必须给 PartFile::f_ 加 strand 或其它串行化保护。
  // 网络线程 co_await post(disk_executor()) 期间挂起, 不阻塞其他 worker 的 socket I/O。
  boost::asio::any_io_executor disk_executor();
  boost::asio::io_context& context();
  void run();
  void restart();
  void stop() noexcept;
  template <class Awaitable>
  void co_spawn_detached(Awaitable&& a){
    boost::asio::co_spawn(context(), std::forward<Awaitable>(a), boost::asio::detached);
  }
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}
