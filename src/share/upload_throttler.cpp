#include "ed2k/share/upload_throttler.hpp"
#include <algorithm>
#include <utility>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace ed2k::share {
namespace asio = boost::asio;

UploadBandwidthThrottler::UploadBandwidthThrottler(asio::any_io_executor executor,
                                                   std::uint64_t bytes_per_second)
  : executor_(std::move(executor)),
    bytes_per_second_(bytes_per_second),
    next_available_(std::chrono::steady_clock::now()) {}

asio::awaitable<void> UploadBandwidthThrottler::acquire(std::uint64_t bytes) {
  if(bytes == 0 || bytes_per_second_ == 0) co_return;

  const auto now = std::chrono::steady_clock::now();
  const auto scheduled = std::max(now, next_available_);
  const long double seconds = static_cast<long double>(bytes) /
                              static_cast<long double>(bytes_per_second_);
  auto reserved = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
    std::chrono::duration<long double>(seconds));
  if(reserved <= std::chrono::steady_clock::duration::zero()) {
    reserved = std::chrono::steady_clock::duration{1};
  }
  next_available_ = scheduled + reserved;

  if(scheduled > now) {
    asio::steady_timer timer(executor_);
    timer.expires_at(scheduled);
    co_await timer.async_wait(asio::use_awaitable);
  }
}

} // namespace ed2k::share
