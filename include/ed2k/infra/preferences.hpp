#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include <tl/expected.hpp>

namespace ed2k::infra {

struct Preferences {
  std::string nickname = "ed2k";
  std::uint16_t tcp_port = 4662;
  std::uint16_t udp_port = 4672;
  std::uint16_t server_udp_port = 4665;
  std::uint32_t upload_limit_bps = 0;
  std::uint32_t download_limit_bps = 0;
  std::uint32_t upload_slots = 3;
  std::uint32_t max_connections = 200;
  std::uint32_t max_sources_per_file = 400;
  std::uint32_t connect_timeout_ms = 15000;
  std::uint32_t request_timeout_ms = 15000;
  std::uint32_t kad_request_timeout_ms = 60000;
  std::uint32_t http_update_interval_minutes = 1440;
  std::uint8_t ip_filter_level = 127;
  bool enable_server = true;
  bool enable_kad = true;
  bool enable_ip_filter = true;
  bool enable_obfuscation = true;
  bool request_obfuscation = false;
  bool require_obfuscation = false;
  bool udp_obfuscation_fallback = true;
  bool auto_update_server_met = false;
  bool auto_update_nodes_dat = false;
  bool auto_update_ipfilter = false;
  bool share_hidden_files = false;
  std::filesystem::path incoming_dir = "incoming";
  std::filesystem::path temp_dir = "temp";
  std::filesystem::path config_dir = ".";
  std::filesystem::path server_met_path = "server.met";
  std::filesystem::path nodes_dat_path = "nodes.dat";
  std::filesystem::path ipfilter_dat_path = "ipfilter.dat";
  std::filesystem::path known_met_path = "known.met";
  std::filesystem::path known2_met_path = "known2.met";
  std::filesystem::path clients_met_path = "clients.met";
  std::filesystem::path stat_dat_path = "statistics.dat";
  std::vector<std::filesystem::path> shared_dirs;

  static Preferences defaults();
  static tl::expected<Preferences, std::error_code> load(const std::filesystem::path& path);
  tl::expected<void, std::error_code> save(const std::filesystem::path& path) const;

  bool operator==(const Preferences&) const = default;
};

} // namespace ed2k::infra
