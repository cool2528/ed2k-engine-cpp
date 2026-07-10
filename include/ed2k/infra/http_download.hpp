#pragma once

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <system_error>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <tl/expected.hpp>

namespace ed2k::infra {

struct HTTPDownloadOptions {
  std::optional<std::filesystem::path> additional_ca_file;
};

class HTTPDownload {
 public:
  explicit HTTPDownload(boost::asio::any_io_executor ex,
                        HTTPDownloadOptions options = {});

  boost::asio::awaitable<tl::expected<void, std::error_code>>
    fetch(const std::string& url,
          const std::filesystem::path& destination,
          std::chrono::milliseconds timeout);

 private:
  boost::asio::any_io_executor executor_;
  HTTPDownloadOptions options_;
};

} // namespace ed2k::infra
