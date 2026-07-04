#pragma once
#include <chrono>
#include <cstdint>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

namespace ed2k::share {

class UploadBandwidthThrottler {
 public:
  UploadBandwidthThrottler(boost::asio::any_io_executor executor,
                           std::uint64_t bytes_per_second);

  boost::asio::awaitable<void> acquire(std::uint64_t bytes);

 private:
  boost::asio::any_io_executor executor_;
  std::uint64_t bytes_per_second_ = 0;
  std::chrono::steady_clock::time_point next_available_;
};

} // namespace ed2k::share
