#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/server/messages.hpp"   // SourceEndpoint
#include "ed2k/server/connection.hpp"  // ServerConnection (M3 LowID callback)
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/peer/inbound_listener.hpp"  // InboundListener (M3 LowID callback)
namespace ed2k::kad {
class KadNetwork;
}
namespace ed2k::download {

class Download {
 public:
  Download(boost::asio::any_io_executor ex, const std::filesystem::path& out,
           const FileHash& hash, std::uint64_t size, const ed2k::server::SourceEndpoint& source);
  void set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level = 127);
  boost::asio::awaitable<tl::expected<void,std::error_code>> run(std::chrono::milliseconds timeout);
 private:
  ed2k::peer::C2CConnection conn_;
  std::filesystem::path out_;
  FileHash hash_;
  std::uint64_t size_;
  ed2k::server::SourceEndpoint source_;
  std::shared_ptr<const infra::IPFilter> ip_filter_;
  std::uint8_t ip_filter_level_ = 127;
};

// R1-3 S2: Builder 构造 + 注入引用替换裸指针。server/listener 用 optional<reference_wrapper>
// 表达「可选、非空即有效、非拥有引用」（替代裸指针的可空/可悬空）。disk_executor 经 Builder
// 注入（替代 set_disk_executor 时序耦合）。旧构造保留 [[deprecated]] 渐进迁移。
class MultiSourceDownload {
 public:
  class Builder {
   public:
    explicit Builder(boost::asio::any_io_executor net_ex) : net_ex_(net_ex), disk_ex_(net_ex) {}
    Builder& out(std::filesystem::path p) { out_ = std::move(p); return *this; }
    Builder& hash(FileHash h) { hash_ = h; return *this; }
    Builder& size(std::uint64_t s) { size_ = s; return *this; }
    Builder& aich(std::optional<AICHHash> a) { aich_ = std::move(a); return *this; }
    Builder& sources(std::vector<server::SourceEndpoint> s) { sources_ = std::move(s); return *this; }
    Builder& server(server::ServerConnection& s) { server_ = std::ref(s); return *this; }
    Builder& listener(peer::InboundListener& l) { listener_ = std::ref(l); return *this; }
    Builder& kad_network(kad::KadNetwork& k) { kad_network_ = std::ref(k); return *this; }
    Builder& disk_executor(boost::asio::any_io_executor ex) { disk_ex_ = ex; return *this; }
    Builder& ip_filter(std::shared_ptr<const infra::IPFilter> f, std::uint8_t level = 127) {
      ip_filter_ = std::move(f);
      ip_filter_level_ = level;
      return *this;
    }
    MultiSourceDownload build();
   private:
    friend class MultiSourceDownload;
    boost::asio::any_io_executor net_ex_, disk_ex_;
    std::filesystem::path out_;
    FileHash hash_{};
    std::uint64_t size_ = 0;
    std::optional<AICHHash> aich_;
    std::vector<server::SourceEndpoint> sources_;
    std::optional<std::reference_wrapper<server::ServerConnection>> server_;
    std::optional<std::reference_wrapper<peer::InboundListener>> listener_;
    std::optional<std::reference_wrapper<kad::KadNetwork>> kad_network_;
    std::shared_ptr<const infra::IPFilter> ip_filter_;
    std::uint8_t ip_filter_level_ = 127;
  };

  [[deprecated("Use MultiSourceDownload::Builder")]]
  MultiSourceDownload(boost::asio::any_io_executor ex,
                      const std::filesystem::path& out,
                      const FileHash& hash, std::uint64_t size,
                      const std::optional<AICHHash>& aich,
                      std::vector<server::SourceEndpoint> sources,
                      server::ServerConnection* server_conn = nullptr,
                      peer::InboundListener* listener = nullptr);

  [[deprecated("Use Builder.disk_executor()")]]
  void set_disk_executor(boost::asio::any_io_executor ex) { disk_ex_ = std::move(ex); }

  boost::asio::awaitable<tl::expected<void,std::error_code>> run(
    std::chrono::milliseconds total_timeout, std::size_t max_retries = 3);

  MultiSourceDownload(const MultiSourceDownload&) = delete;
  MultiSourceDownload& operator=(const MultiSourceDownload&) = delete;
  MultiSourceDownload(MultiSourceDownload&&) noexcept = default;
  MultiSourceDownload& operator=(MultiSourceDownload&&) noexcept = default;
 private:
  MultiSourceDownload(boost::asio::any_io_executor net_ex,
                      boost::asio::any_io_executor disk_ex,
                      std::filesystem::path out, FileHash hash, std::uint64_t size,
                      std::optional<AICHHash> aich,
                      std::vector<server::SourceEndpoint> sources,
                      std::optional<std::reference_wrapper<server::ServerConnection>> server_conn,
                      std::optional<std::reference_wrapper<peer::InboundListener>> listener,
                      std::optional<std::reference_wrapper<kad::KadNetwork>> kad_network,
                      std::shared_ptr<const infra::IPFilter> ip_filter,
                      std::uint8_t ip_filter_level)
    : ex_(net_ex), disk_ex_(disk_ex), out_(std::move(out)), hash_(hash), size_(size),
      aich_(std::move(aich)), sources_(std::move(sources)),
      server_conn_(std::move(server_conn)), listener_(std::move(listener)),
      kad_network_(std::move(kad_network)), ip_filter_(std::move(ip_filter)),
      ip_filter_level_(ip_filter_level) {}
  boost::asio::any_io_executor ex_;
  boost::asio::any_io_executor disk_ex_;   // 默认 = ex_ (同步等效), Builder.disk_executor 注入 disk 池
  std::filesystem::path out_;
  FileHash hash_;
  std::uint64_t size_;
  std::optional<AICHHash> aich_;
  std::vector<server::SourceEndpoint> sources_;
  std::optional<std::reference_wrapper<server::ServerConnection>> server_conn_;
  std::optional<std::reference_wrapper<peer::InboundListener>> listener_;
  std::optional<std::reference_wrapper<kad::KadNetwork>> kad_network_;
  std::shared_ptr<const infra::IPFilter> ip_filter_;
  std::uint8_t ip_filter_level_ = 127;
  friend class Builder;
};

}
