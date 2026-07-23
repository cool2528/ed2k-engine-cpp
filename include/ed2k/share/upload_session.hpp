#pragma once
#include <chrono>
#include <memory>
#include <optional>
#include <system_error>
#include <tl/expected.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/net/connection.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/share/client_credits.hpp"
#include "ed2k/share/known_file.hpp"
#include "ed2k/share/upload_queue.hpp"
#include "ed2k/share/upload_throttler.hpp"

namespace ed2k::share {

class UploadSession {
 public:
  UploadSession(ed2k::peer::C2CConnection&& connection,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self);
  UploadSession(ed2k::peer::C2CConnection&& connection,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor,
                UploadQueue* queue = nullptr,
                UploadBandwidthThrottler* throttler = nullptr,
                ClientCredits* credits = nullptr);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor,
                UploadQueue* queue);
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor,
                UploadQueue* queue,
                UploadBandwidthThrottler* throttler);
  // udp_reask_port(P2c A8): 本会话向对端通告的 UDP reask 端口(EMULEINFOANSWER 的 MuleInfo.udp_port)
  // ——只有调用方(Session::Impl::run_upload)确认自己的 UDP reask 应答 socket(share_udp_)真的
  // 绑定成功时才应传入非 0 值; 默认 0(如实通告"不可达", 与其余构造函数/既有调用方完全一致的
  // 降级行为, 见 handle() 内 EMULEINFO 分支与 download.cpp::default_mule_info() 的对称注释)。
  UploadSession(boost::asio::ip::tcp::socket&& socket,
                KnownFileDB& files,
                ed2k::peer::HelloInfo self,
                boost::asio::any_io_executor disk_executor,
                UploadQueue* queue,
                UploadBandwidthThrottler* throttler,
                ClientCredits* credits,
                std::uint16_t udp_reask_port = 0);

  boost::asio::awaitable<tl::expected<void, std::error_code>>
    run(std::chrono::milliseconds timeout);
  void set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level = 127);

 private:
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    handshake(std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    handle(const ed2k::net::Packet& pkt);
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    send_not_found(const ed2k::FileHash& hash);
  boost::asio::awaitable<tl::expected<std::vector<std::byte>, std::error_code>>
    read_range(const KnownFile& file, std::uint64_t start, std::uint64_t end);
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    send_requested_parts(const KnownFile& file, const ed2k::peer::RequestParts& req);

  ed2k::peer::C2CConnection conn_;
  KnownFileDB& files_;
  ed2k::peer::HelloInfo self_;
  std::optional<ed2k::peer::HelloInfo> peer_;
  std::optional<ed2k::FileHash> current_file_;
  boost::asio::any_io_executor disk_executor_;
  UploadQueue* queue_ = nullptr;
  UploadBandwidthThrottler* throttler_ = nullptr;
  ClientCredits* credits_ = nullptr;
  std::shared_ptr<const infra::IPFilter> ip_filter_;
  std::uint8_t ip_filter_level_ = 127;
  // P2c A8: 本会话向对端通告的 UDP reask 端口; 0 = 不可达(降级为纯 TCP)。
  std::uint16_t udp_reask_port_ = 0;
  // P2c A8: 当前是否处于"已答 QUEUERANKING, 尚未 ACCEPTUPLOADREQ"的排队态; run() 主循环据此把
  // recv_packet 的等待预算收紧为短轮询, 每轮顺带重新检查槽位是否已释放(见 run() 实现注释)。
  bool is_queued_ = false;
  // is_queued_ 为真时, 排队中的具体文件 hash(供轮询重新调用 queue_->enqueue() 用)。
  std::optional<ed2k::FileHash> queued_hash_;
};

} // namespace ed2k::share
