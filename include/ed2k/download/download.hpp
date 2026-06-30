#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/server/messages.hpp"   // SourceEndpoint
#include "ed2k/peer/c2c_connection.hpp"
namespace ed2k::download {
class Download {
 public:
  Download(boost::asio::any_io_executor ex, const std::filesystem::path& out,
           const FileHash& hash, std::uint64_t size, const ed2k::server::SourceEndpoint& source);
  boost::asio::awaitable<tl::expected<void,std::error_code>> run(std::chrono::milliseconds timeout);
 private:
  ed2k::peer::C2CConnection conn_;
  std::filesystem::path out_;
  FileHash hash_;
  std::uint64_t size_;
  ed2k::server::SourceEndpoint source_;
};
}
