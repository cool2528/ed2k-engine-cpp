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
#include "ed2k/kad/routing_table.hpp"  // kad::Contact (B4: kad_peers 快照)
#include "ed2k/server/messages.hpp"   // SourceEndpoint
#include "ed2k/server/connection.hpp"  // ServerConnection (M3 LowID callback)
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/peer/inbound_listener.hpp"  // InboundListener (M3 LowID callback)
#include "ed2k/peer/peer_reask.hpp"    // peer::kReaskInterval (P2c A8: run() 排队保活周期默认值)
namespace ed2k::kad {
class KadNetwork;
struct KadSearchEntry;
}
namespace ed2k::download {

std::optional<peer::PeerIdentity>
peer_identity_from_kad_source(const kad::KadSearchEntry& entry);

// GUI 进度回调: (已完成字节, 总字节)。在网络线程触发, 调用方负责跨线程转投。
using ProgressFn = std::function<void(std::uint64_t bytes_done, std::uint64_t total)>;

// Task 6(源重试/重连 + 编排周期重问)的默认时间参数, 经 MultiSourceDownload::run() 的对应
// 形参暴露(与既有 max_retries 同一模式: 生产调用方用默认值, 测试可传入更短的间隔避免真实
// 等待, 无需为此新增 Builder 旋钮/破坏既有构造链)。
// kSourceReaskInterval:   编排监督重新 get_sources 的周期(eMule 惯例"每隔几分钟重问服务器")。
// kSourceReconnectBackoff: peer_worker 对同源 transient 失败重连前的退避等待(固定值, 非指数)。
inline constexpr std::chrono::milliseconds kSourceReaskInterval{std::chrono::minutes(3)};
inline constexpr std::chrono::milliseconds kSourceReconnectBackoff{5000};

class Download {
 public:
  Download(boost::asio::any_io_executor ex, const std::filesystem::path& out,
           const FileHash& hash, std::uint64_t size, const ed2k::server::SourceEndpoint& source);
  Download(boost::asio::any_io_executor ex, const std::filesystem::path& out,
           const FileHash& hash, std::uint64_t size, peer::PeerIdentity source,
           peer::ObfuscationPolicy policy, std::optional<UserHash> local_user_hash = std::nullopt);
  void set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level = 127);
  boost::asio::awaitable<tl::expected<void,std::error_code>> run(std::chrono::milliseconds timeout);
  // 源在 mule-info 握手中通告的 UDP 端口 (ET_UDPPORT); run() 成功前恒为 0。0 表示对端未
  // 通告 (纯 eDonkey 客户端/交换失败, 见 handshake_with_mule_info 的优雅降级) ——
  // 供未来的 UDP reask 排队保活寻址 (Task 4), 本任务只负责捕获与暴露。
  std::uint16_t source_udp_port() const noexcept { return source_udp_port_; }
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
  std::uint16_t source_udp_port_ = 0;
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
    // B4: kad_network 自身路由表为空的 ephemeral 实例场景下, run() 不能再靠
    // kad_network.routing_table().closest_to(...) 取 peers(结果恒为空)——peers 必须由调用方
    // 从"主"路由表(如 Session::Impl::kad, 与 ephemeral 查询实例分离)显式快照后传入。
    Builder& kad_peers(std::vector<kad::Contact> p) { kad_peers_ = std::move(p); return *this; }
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
    std::vector<kad::Contact> kad_peers_;
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

  // peer_reask_interval(P2c A8): 排队等待循环里"TCP 静默多久才发一次 UDP REASKFILEPING 保活"的
  // 周期; 生产默认 peer::kReaskInterval(60s, eMule 惯例)。测试可传短值, 避免真实等待一整分钟
  // 才走到 engine-to-engine 排队/reask 场景(见 session_test.cpp 的 EngineToEngine 用例)。
  boost::asio::awaitable<tl::expected<void,std::error_code>> run(
    std::chrono::milliseconds total_timeout, std::size_t max_retries = 3,
    std::chrono::milliseconds source_reask_interval = kSourceReaskInterval,
    std::chrono::milliseconds source_reconnect_backoff = kSourceReconnectBackoff,
    std::chrono::milliseconds peer_reask_interval = peer::kReaskInterval);

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
                      std::vector<kad::Contact> kad_peers,
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
