#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/server/connection.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/download/download.hpp"
#include "ed2k/link/ed2k_link.hpp"
namespace ed2k::app {
struct ServerTarget { IPv4 ip; std::uint16_t port = 0; };
struct LoginSession {
  ed2k::server::ServerConnection conn;
  ed2k::server::LoginResult result;
};
std::vector<ServerTarget> fallback_servers();
std::vector<ServerTarget> build_targets(std::span<const std::byte> server_met_bytes,
                                        std::optional<ServerTarget> override);
boost::asio::awaitable<tl::expected<LoginSession, std::error_code>>
  login_with_rotation(boost::asio::any_io_executor ex,
                      std::span<const std::byte> server_met_bytes,
                      std::optional<ServerTarget> override,
                      const ed2k::server::LoginParams& p,
                      std::chrono::milliseconds per_server_timeout);

// M2 download orchestration options. client_port is the InboundListener port
// (M3, Task 7); M2 only exercises HighID sources so it is unused on the wire.
struct DownloadOpts {
  std::filesystem::path out_path;
  std::chrono::milliseconds per_server_timeout = std::chrono::seconds(30);
  std::chrono::milliseconds total_timeout = std::chrono::seconds(120);
  std::uint16_t client_port = 4662;
};
// Keep sources whose id is a HighID (!low_id(), i.e. id >= 0x1000000).
// 保留定义供 CLI/测试复用; download_link 本身(M3)不再调用——LowID 源留给回调路径。
std::vector<ed2k::server::SourceEndpoint>
  filter_high_id(const std::vector<ed2k::server::SourceEndpoint>& sources);
// login_with_rotation -> get_sources(link.hash,link.size) -> (保留全部源, 不 filter)
// -> InboundListener(ex,opts.client_port) + MultiSourceDownload(aich=nullopt, part-MD4 路径,
//    server_conn=&lg->conn, listener=&listener).run(total_timeout, 3)。
// M3: HighID 源走 peer_worker 直连, LowID 源走 callback_request+listener.accept 回调。
boost::asio::awaitable<tl::expected<void, std::error_code>>
  download_link(boost::asio::any_io_executor ex,
                const ed2k::Ed2kFileLink& link,
                std::span<const std::byte> server_met_bytes,
                std::optional<ServerTarget> server_override,
                const DownloadOpts& opts);
}
