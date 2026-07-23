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
  // P4c-3 M3/R1-3 S3: disk/hash offload thread pool. Stays single-threaded (disk_pool_thread_count) as a
  // simplicity/perf choice, not a correctness requirement any more: audit C9 gave PartFile its own strand
  // over disk_ex, so PartFile::f_ access is serialized even if this pool were configured multi-threaded
  // (defense in depth). Other disk_executor() consumers (UploadSession, Statistics::async_flush) open a
  // fresh local stream per call rather than sharing one member stream, so they were never exposed to this
  // particular fstream race.
  // Network thread suspends during co_await post(disk_executor()), not blocking other workers' socket I/O.
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
