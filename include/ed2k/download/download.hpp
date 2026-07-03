#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <atomic>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/server/messages.hpp"   // SourceEndpoint
#include "ed2k/server/connection.hpp"  // ServerConnection (M3 LowID callback)
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/peer/inbound_listener.hpp"  // InboundListener (M3 LowID callback)
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

class MultiSourceDownload {
 public:
  MultiSourceDownload(boost::asio::any_io_executor ex,
                      const std::filesystem::path& out,
                      const FileHash& hash, std::uint64_t size,
                      const std::optional<AICHHash>& aich,
                      std::vector<server::SourceEndpoint> sources,
                      server::ServerConnection* server_conn = nullptr,
                      peer::InboundListener* listener = nullptr);
  // P4c-3 M3: 注入磁盘卸载线程池 ex (IoRuntime::disk_executor())。
  // 未调用时 disk_ex_==ex_ → write_block_async 退化为 post(net) 同步等效 (测试默认路径)。
  void set_disk_executor(boost::asio::any_io_executor ex) { disk_ex_ = std::move(ex); }
  boost::asio::awaitable<tl::expected<void,std::error_code>> run(
    std::chrono::milliseconds total_timeout,
    std::size_t max_retries = 3);
 private:
  boost::asio::any_io_executor ex_;
  boost::asio::any_io_executor disk_ex_;   // M3: 默认 = ex_ (同步等效), set_disk_executor 注入 disk 池
  std::filesystem::path out_;
  FileHash hash_;
  std::uint64_t size_;
  std::optional<AICHHash> aich_;
  std::vector<server::SourceEndpoint> sources_;
  server::ServerConnection* server_conn_ = nullptr;
  peer::InboundListener* listener_ = nullptr;
};

}
