#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/infra/proxy.hpp"
#include "ed2k/server/connection.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/download/download.hpp"
#include "ed2k/link/ed2k_link.hpp"
namespace ed2k::kad {
class KadNetwork;
}
namespace ed2k::app {
struct ServerTarget {
  IPv4 ip;
  std::uint16_t port = 0;
  std::uint32_t udp_flags = 0;
  std::uint32_t udp_key = 0;
  std::uint32_t udp_key_ip = 0;
  std::uint16_t tcp_obf_port = 0;
  std::uint16_t udp_obf_port = 0;
};
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
                      std::chrono::milliseconds per_server_timeout,
                      std::optional<ed2k::infra::ProxyConfig> proxy = std::nullopt,
                      std::shared_ptr<const ed2k::infra::IPFilter> ip_filter = nullptr,
                      std::uint8_t ip_filter_level = 127);

// M2 download orchestration options. client_port is the InboundListener port
// (M3, Task 7); M2 only exercises HighID sources so it is unused on the wire.
struct DownloadOpts {
  std::filesystem::path out_path;
  std::chrono::milliseconds per_server_timeout = std::chrono::seconds(30);
  std::chrono::milliseconds total_timeout = std::chrono::seconds(120);
  std::uint16_t client_port = 4662;
  std::optional<std::reference_wrapper<ed2k::kad::KadNetwork>> kad_network;
  std::optional<ed2k::infra::ProxyConfig> proxy;
  std::shared_ptr<const ed2k::infra::IPFilter> ip_filter;
  std::uint8_t ip_filter_level = 127;
  ed2k::peer::ObfuscationPolicy obfuscation_policy = ed2k::peer::ObfuscationPolicy::disabled;
  std::optional<ed2k::UserHash> local_user_hash;
};
// Keep sources whose id is a HighID (!low_id(), i.e. id >= 0x1000000).
// Definition kept for CLI/test reuse; download_link itself (M3) no longer calls this -- LowID sources go through the callback path.
std::vector<ed2k::server::SourceEndpoint>
  filter_high_id(const std::vector<ed2k::server::SourceEndpoint>& sources);
// login_with_rotation -> get_sources(link.hash,link.size) -> (keep all sources, no filter)
// -> construct InboundListener(ex,opts.client_port) only when LowID sources exist (Fix M3: avoid
//    unconditional bind for HighID-only downloads, preventing system_error from port conflicts
//    regressing the HighID path)
//    + MultiSourceDownload(aich=nullopt, part-MD4 path, server_conn=&lg->conn,
//    listener= has_low_id?&listener:nullptr).run(total_timeout, 3).
// M3: HighID sources use peer_worker direct connect; LowID sources use callback_request+listener.accept callback.
boost::asio::awaitable<tl::expected<void, std::error_code>>
  download_link(boost::asio::any_io_executor ex,
                const ed2k::Ed2kFileLink& link,
                std::span<const std::byte> server_met_bytes,
                std::optional<ServerTarget> server_override,
                const DownloadOpts& opts);
}
