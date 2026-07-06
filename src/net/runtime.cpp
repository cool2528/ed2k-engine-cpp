#include "ed2k/net/runtime.hpp"
#include <boost/asio/thread_pool.hpp>

namespace ed2k::net {
struct IoRuntime::Impl {
  boost::asio::io_context ctx;
  boost::asio::thread_pool disk_pool{disk_pool_thread_count};   // 单线程串行 f_
};

IoRuntime::IoRuntime() : impl_(std::make_unique<Impl>()) {}
IoRuntime::~IoRuntime() = default;

boost::asio::any_io_executor IoRuntime::executor() { return impl_->ctx.get_executor(); }
boost::asio::any_io_executor IoRuntime::disk_executor() { return impl_->disk_pool.get_executor(); }
boost::asio::io_context& IoRuntime::context() { return impl_->ctx; }
void IoRuntime::run() { impl_->ctx.run(); }
void IoRuntime::restart() { impl_->ctx.restart(); }
void IoRuntime::stop() noexcept { impl_->ctx.stop(); }
}
