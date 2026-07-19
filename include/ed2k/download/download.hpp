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
struct KadSearchEntry;
}
namespace ed2k::download {

std::optional<peer::PeerIdentity>
peer_identity_from_kad_source(const kad::KadSearchEntry& entry);

// GUI 进度回调: (已完成字节, 总字节)。在网络线程触发, 调用方负责跨线程转投。
using ProgressFn = std::function<void(std::uint64_t bytes_done, std::uint64_t total)>;

class Download {
 public:
  Download(boost::asio::any_io_executor ex, const std::filesystem::path& out,
           const FileHash& hash, std::uint64_t size, const ed2k::server::SourceEndpoint& source);
  Download(boost::asio::any_io_executor ex, const std::filesystem::path& out,
           const FileHash& hash, std::uint64_t size, peer::PeerIdentity source,
           peer::ObfuscationPolicy policy, std::optional<UserHash> local_user_hash = std::nullopt);
  void set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level = 127);
  boost::asio::awaitable<tl::expected<void,std::error_code>> run(std::chrono::milliseconds timeout);
 private:
  ed2k::peer::C2CConnection conn_;
  std::filesystem::path out_;
  FileHash hash_;
  std::uint64_t size_;
  peer::PeerIdentity source_;
  peer::ObfuscationPolicy obfuscation_policy_ = peer::ObfuscationPolicy::disabled;
  std::optional<UserHash> local_user_hash_;
  std::shared_ptr<const infra::IPFilter> ip_filter_;
  std::uint8_t ip_filter_level_ = 127;
};

// R1-3 S2: Builder construction + injected references replace raw pointers. server/listener use
// optional<reference_wrapper> to express "optional, non-null-means-valid, non-owning reference"
// (replacing nullable/dangling raw pointers). disk_executor is injected via Builder (replacing
// set_disk_executor temporal coupling). Old constructor kept [[deprecated]] for gradual migration.
class MultiSourceDownload {
 public:
  class Builder {
   public:
    explicit Builder(boost::asio::any_io_executor net_ex) : net_ex_(net_ex), disk_ex_(net_ex) {}
    Builder& out(std::filesystem::path p) { out_ = std::move(p); return *this; }
    Builder& hash(FileHash h) { hash_ = h; return *this; }
    Builder& size(std::uint64_t s) { size_ = s; return *this; }
    Builder& aich(std::optional<AICHHash> a) { aich_ = std::move(a); return *this; }
    Builder& sources(std::vector<server::SourceEndpoint> s) {
      sources_.clear(); sources_.reserve(s.size());
      for (auto& endpoint : s) sources_.push_back(peer::PeerIdentity{endpoint, std::nullopt});
      return *this;
    }
    Builder& sources(std::vector<peer::PeerIdentity> s) { sources_ = std::move(s); return *this; }
    Builder& peer_sources(std::vector<peer::PeerSource> s) {
      sources_.clear(); sources_.reserve(s.size());
      for (const auto& source : s) sources_.push_back(peer::peer_identity(source));
      return *this;
    }
    Builder& obfuscation(peer::ObfuscationPolicy policy, std::optional<UserHash> local_user_hash) {
      obfuscation_policy_ = policy;
      local_user_hash_ = std::move(local_user_hash);
      return *this;
    }
    Builder& server(server::ServerConnection& s) { server_ = std::ref(s); return *this; }
    Builder& listener(peer::InboundListener& l) { listener_ = std::ref(l); return *this; }
    Builder& kad_network(kad::KadNetwork& k) { kad_network_ = std::ref(k); return *this; }
    Builder& disk_executor(boost::asio::any_io_executor ex) { disk_ex_ = ex; return *this; }
    Builder& ip_filter(std::shared_ptr<const infra::IPFilter> f, std::uint8_t level = 127) {
      ip_filter_ = std::move(f);
      ip_filter_level_ = level;
      return *this;
    }
    Builder& on_progress(ProgressFn fn) { on_progress_ = std::move(fn); return *this; }
    Builder& stop_flag(std::shared_ptr<const bool> flag) { stop_ = std::move(flag); return *this; }
    MultiSourceDownload build();
   private:
    friend class MultiSourceDownload;
    boost::asio::any_io_executor net_ex_, disk_ex_;
    std::filesystem::path out_;
    FileHash hash_{};
    std::uint64_t size_ = 0;
    std::optional<AICHHash> aich_;
    std::vector<peer::PeerIdentity> sources_;
    peer::ObfuscationPolicy obfuscation_policy_ = peer::ObfuscationPolicy::disabled;
    std::optional<UserHash> local_user_hash_;
    std::optional<std::reference_wrapper<server::ServerConnection>> server_;
    std::optional<std::reference_wrapper<peer::InboundListener>> listener_;
    std::optional<std::reference_wrapper<kad::KadNetwork>> kad_network_;
    std::shared_ptr<const infra::IPFilter> ip_filter_;
    std::uint8_t ip_filter_level_ = 127;
    ProgressFn on_progress_;
    std::shared_ptr<const bool> stop_;
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
  void set_disk_executor(boost::asio::any_io_executor ex);

  boost::asio::awaitable<tl::expected<void,std::error_code>> run(
    std::chrono::milliseconds total_timeout, std::size_t max_retries = 3);

  MultiSourceDownload(const MultiSourceDownload&) = delete;
  MultiSourceDownload& operator=(const MultiSourceDownload&) = delete;
  ~MultiSourceDownload();
  MultiSourceDownload(MultiSourceDownload&&) noexcept;
  MultiSourceDownload& operator=(MultiSourceDownload&&) noexcept;
 private:
  MultiSourceDownload(boost::asio::any_io_executor net_ex,
                      boost::asio::any_io_executor disk_ex,
                      std::filesystem::path out, FileHash hash, std::uint64_t size,
                      std::optional<AICHHash> aich,
                      std::vector<peer::PeerIdentity> sources,
                      std::optional<std::reference_wrapper<server::ServerConnection>> server_conn,
                      std::optional<std::reference_wrapper<peer::InboundListener>> listener,
                      std::optional<std::reference_wrapper<kad::KadNetwork>> kad_network,
                      std::shared_ptr<const infra::IPFilter> ip_filter,
                      std::uint8_t ip_filter_level,
                      peer::ObfuscationPolicy obfuscation_policy,
                      std::optional<UserHash> local_user_hash,
                      ProgressFn on_progress,
                      std::shared_ptr<const bool> stop);
  struct Impl;
  std::unique_ptr<Impl> impl_;
  friend class Builder;
};

}
